export interface EnvironmentAliases {
  [alias: string]: string;
}

export const defaultAliases: EnvironmentAliases = {
  prod: 'production',
  dev: 'development',
};

const defaultCurrentEnvironmentVariableNames = ['APP_CONFIG_ENV', 'NODE_ENV', 'ENV'];

export function currentEnvironment(
  aliases: EnvironmentAliases = defaultAliases,
  currentEnvironmentVariableNames: string[] = defaultCurrentEnvironmentVariableNames,
) {
  let value: string | undefined;

  for (const variableName of currentEnvironmentVariableNames) {
    if ((value = process.env[variableName])) {
      break;
    }
  }

  if (!value) return undefined;

  if (aliases[value]) {
    return aliases[value];
  }

  return value;
}
