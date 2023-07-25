import { awscdk } from 'projen';
const project = new awscdk.AwsCdkConstructLibrary({
  author: 'durkinza',
  authorAddress: '8985088+durkinza@users.noreply.github.com',
  cdkVersion: '2.79.0',
  defaultReleaseBranch: 'main',
  jsiiVersion: '~5.0.0',
  name: '@durkinza/cdk-networkfirewall-l2',
  packageName: '@durkinza/cdk-networkfirewall-l2', /* The "name" in package.json. */
  license: 'Apache-2.0',
  projenrcTs: true,
  repositoryUrl: 'https://github.com/durkinza/cdk-networkfirewall-l2.git',
  keywords: [
    'cdk',
    'aws-cdk',
    'networkfirewall',
    'aws',
    'awscdk',
  ],
  publishToPypi: {
    distName: 'durkinza.cdk-networkfirewall-l2',
    module: 'durkinza.cdk_networkfirewall_l2',
  },
  stability: 'experimental',
  deps: ['aws-cdk-lib'], /* Runtime dependencies of this module. */
  description: 'Experimental L2 constructs for the aws-networkfirewall', /* The description is just a string that helps people understand the purpose of the package. */
  devDeps: [
    '@types/jest',
    '@types/node',
    '@typescript-eslint/eslint-plugin',
    '@typescript-eslint/parser',
    'constructs',
    'eslint',
    'eslint-import-resolver-node',
    'eslint-import-resolver-typescript',
    'eslint-plugin-import',
    'jest',
    'jest-junit',
    'jsii',
    'jsii-diff',
    'jsii-docgen',
    'jsii-pacmak',
    'jsii-rosetta',
    'npm-check-updates',
    'projen',
    'standard-version',
    'ts-jest',
    'ts-node',
    'typescript',
  ], /* Build dependencies for this module. */
});
project.gitignore.include('.jsii');
project.gitignore.exclude('test/**/*.js');
project.gitignore.exclude('test/**/*.d.ts');

project.synth();