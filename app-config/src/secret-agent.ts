import http from 'http';
import https from 'https';
import WebSocket from 'ws';
import { resolve } from 'path';
import * as fs from 'fs-extra';
import { Server as BaseServer, Client as BaseClient, MessageVariant } from '@lcdev/ws-rpc/bson';
import { Json } from './common';
import {
  Key,
  decryptValue,
  encryptValue,
  loadSymmetricKeys,
  loadPrivateKeyLazy,
  decryptSymmetricKey,
  EncryptedSymmetricKey,
} from './encryption';
import { loadOrCreateCert } from './secret-agent-tls';
import { loadSettingsLazy, saveSettings } from './settings';
import { AppConfigError } from './errors';
import { logger } from './logging';

export enum MessageType {
  Ping = 'Ping',
  Decrypt = 'Decrypt',
  Encrypt = 'Encrypt',
}

export type Messages = {
  [MessageType.Ping]: MessageVariant<MessageType.Ping, void, void>;
  [MessageType.Decrypt]: MessageVariant<
    MessageType.Decrypt,
    {
      text: string;
      symmetricKey: EncryptedSymmetricKey;
    },
    Json
  >;
  [MessageType.Encrypt]: MessageVariant<
    MessageType.Encrypt,
    { value: Json; symmetricKey: EncryptedSymmetricKey },
    string
  >;
};

export type EventType = never;
export type Events = never;

export class Client extends BaseClient<MessageType, EventType, Messages, Events> {}
export class Server extends BaseServer<MessageType, EventType, Messages, Events> {}

type ConnectionOptions = { port: number } | { socket: string };

export async function startAgent(
  override?: ConnectionOptions,
  privateKeyOverride?: Key,
): Promise<Server> {
  let privateKey: Key;

  if (privateKeyOverride) {
    privateKey = privateKeyOverride;
  } else {
    privateKey = await loadPrivateKeyLazy();
  }

  const options = await getAgentOptions(override);

  let server: Server;
  if ('port' in options) {
    const { port } = options;
    logger.info(`Starting secret-agent, listening on port ${port}`);

    const { cert, key } = await loadOrCreateCert();
    const httpsServer = https.createServer({ cert, key });

    server = new Server(new WebSocket.Server({ server: httpsServer }));

    const superClose = server.close.bind(server);

    Object.assign(server, {
      async close() {
        await superClose();

        // we have to close the http server ourselves, because it was created manually
        await new Promise<void>((resolve, reject) =>
          httpsServer.close((err) => {
            if (err) reject(err);
            else resolve();
          }),
        );
      },
    });

    httpsServer.listen(port);
  } else {
    const socket = resolve(options.socket);
    logger.info(`Starting secret-agent, listening on unix socket ${socket}`);

    const httpServer = http.createServer();

    server = new Server(new WebSocket.Server({ server: httpServer }));

    const superClose = server.close.bind(server);

    Object.assign(server, {
      async close() {
        await superClose();

        // we have to close the http server ourselves, because it was created manually
        await new Promise<void>((resolve, reject) =>
          httpServer.close((err) => {
            if (err) reject(err);
            else resolve();
          }),
        );
      },
    });

    await fs.remove(socket);
    httpServer.listen(socket);
  }

  server.registerHandler(MessageType.Ping, () => {});

  server.registerHandler(MessageType.Decrypt, async ({ text, symmetricKey }) => {
    logger.verbose(`Decrypting a secret for a key rev:${symmetricKey.revision}`);

    const decoded = await decryptValue(text, await decryptSymmetricKey(symmetricKey, privateKey));

    return decoded;
  });

  server.registerHandler(MessageType.Encrypt, async ({ value, symmetricKey }) => {
    logger.verbose(`Encrypting a secret value with key rev:${symmetricKey.revision}`);

    const encoded = await encryptValue(value, await decryptSymmetricKey(symmetricKey, privateKey));

    return encoded;
  });

  return server;
}

export async function connectAgent(
  closeTimeoutMs = Infinity,
  override?: ConnectionOptions,
  loadEncryptedKey: typeof loadSymmetricKey = loadSymmetricKey,
) {
  const options = await getAgentOptions(override);

  let client: Client;
  if ('port' in options) {
    const { port } = options;
    logger.verbose(`Connecting to secret-agent on port ${port}`);

    const { cert } = await loadOrCreateCert();
    client = new Client(new WebSocket(`wss://localhost:${port}`, { ca: [cert] }));
  } else {
    client = new Client(new WebSocket(`ws+unix://${resolve(options.socket)}`));
  }

  await client.waitForConnection();

  let isClosed = false;
  let closeTimeout: NodeJS.Timeout;

  client.onClose(() => {
    isClosed = true;
  });

  const keepAlive = () => {
    if (closeTimeout) clearTimeout(closeTimeout);
    if (closeTimeoutMs === Infinity) return;

    closeTimeout = setTimeout(() => {
      logger.verbose('Closing websocket');

      client.close().finally(() => {
        logger.verbose('Client was closed');
      });
    }, closeTimeoutMs);
  };

  return {
    close() {
      isClosed = true;
      return client.close();
    },
    isClosed() {
      return isClosed;
    },
    async ping() {
      keepAlive();

      await client.call(MessageType.Ping, undefined);
    },
    async decryptValue(text: string) {
      keepAlive();

      const revision = text.split(':')[1];
      const revisionNumber = parseFloat(revision);

      if (Number.isNaN(revisionNumber)) {
        throw new AppConfigError(
          `Encrypted value was invalid, revision was not a number (${revision})`,
        );
      }

      const symmetricKey = await loadEncryptedKey(revisionNumber);
      const decrypted = await client.call(MessageType.Decrypt, { text, symmetricKey });

      keepAlive();

      return decrypted;
    },
    async encryptValue(value: Json, symmetricKey: EncryptedSymmetricKey) {
      keepAlive();

      const encoded = await client.call(MessageType.Encrypt, { value, symmetricKey });

      keepAlive();

      return encoded;
    },
  } as const;
}

const clients = new Map<number | string, ReturnType<typeof connectAgent>>();

export async function connectAgentLazy(
  closeTimeoutMs = 500,
  override?: ConnectionOptions,
): ReturnType<typeof connectAgent> {
  const options = await getAgentOptions(override);
  const id = 'port' in options ? options.port : options.socket;

  if (!clients.has(id)) {
    const connection = connectAgent(closeTimeoutMs, options);

    clients.set(id, connection);

    return connection;
  }

  const connection = await clients.get(id)!;

  // re-connect
  if (connection.isClosed()) {
    clients.delete(id);

    return connectAgentLazy(closeTimeoutMs, options);
  }

  return connection;
}

export async function disconnectAgents() {
  for (const [port, client] of clients.entries()) {
    clients.delete(port);
    await client.then(
      (c) => c.close(),
      () => {},
    );
  }
}

let useSecretAgent = true;

export function shouldUseSecretAgent(value?: boolean) {
  if (value !== undefined) {
    useSecretAgent = value;
  }

  return useSecretAgent;
}

const defaultPort = 42938;

async function getAgentOptions(override?: ConnectionOptions): Promise<ConnectionOptions> {
  if (override !== undefined) {
    return override;
  }

  const settings = await loadSettingsLazy();

  if (settings.secretAgent) {
    if ('port' in settings.secretAgent && settings.secretAgent.port) {
      return { port: settings.secretAgent.port };
    }

    // setup default settings
    await saveSettings({
      ...settings,
      secretAgent: {
        ...settings.secretAgent,
        port: defaultPort,
      },
    });
  }

  return { port: defaultPort };
}

async function loadSymmetricKey(revision: number): Promise<EncryptedSymmetricKey> {
  const symmetricKeys = await loadSymmetricKeys(true);
  const symmetricKey = symmetricKeys.find((k) => k.revision === revision);

  if (!symmetricKey) throw new AppConfigError(`Could not find symmetric key ${revision}`);

  return symmetricKey;
}
