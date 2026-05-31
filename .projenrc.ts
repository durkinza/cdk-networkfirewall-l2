import { CSpell, Husky, Commitlint } from "@mountainpass/cool-bits-for-projen";
import { awscdk, javascript } from "projen";
const project = new awscdk.AwsCdkConstructLibrary({
  author: "durkinza",
  authorAddress: "8985088+durkinza@users.noreply.github.com",
  bugsUrl: "https://github.com/durkinza/cdk-networkfirewall-l2/issues",
  cdkVersion: "2.257.0",
  minNodeVersion: "16.0.0",
  workflowNodeVersion: "latest",
  defaultReleaseBranch: "main",
  dependabot: true,
  deps: ["aws-cdk-lib"] /* Runtime dependencies of this module. */,
  description:
    "AWS CDK L2 constructs for the AWS Network Firewall (AWS::NetworkFirewall)" /* The description is just a string that helps people understand the purpose of the package. */,
  vscode: true,
  devDeps: [
    "@eslint/compat",
    "@mountainpass/cool-bits-for-projen",
    "@types/jest",
    "@types/node",
    "@types/filesystem",
    "@typescript-eslint/eslint-plugin",
    "@typescript-eslint/parser",
    "aws-cdk-lib",
    "constructs",
    "eslint",
    "eslint-import-resolver-node",
    "eslint-import-resolver-typescript",
    "eslint-plugin-import",
    "jest",
    "jest-junit",
    "jsii",
    "jsii-diff",
    "jsii-docgen",
    "jsii-pacmak",
    "jsii-rosetta",
    "npm-check-updates",
    "projen",
    "standard-version",
    "ts-jest",
    "ts-node",
    "typescript",
    "rimraf",
  ] /* Build dependencies for this module. */,
  packageManager: javascript.NodePackageManager.YARN_CLASSIC,
  homepage: "https://github.com/durkinza/cdk-networkfirewall-l2#readme",
  jsiiVersion: "~5.9.0",
  keywords: [
    "cdk",
    "aws-cdk",
    "networkfirewall",
    "aws-networkfirewall",
    "AWS::NetworkFirewall",
    "aws",
    "awscdk",
    "L2",
    "Network",
    "Firewall",
    "Logging",
    "Security",
  ],
  license: "Apache-2.0",
  majorVersion: 1,
  name: "@durkinza/cdk-networkfirewall-l2",
  npmAccess: javascript.NpmAccess.PUBLIC,
  npmignore: [
    ".devcontainer",
    ".github",
    ".husky",
    "test",
    "test-reports",
    "coverage",
  ],
  packageName:
    "@durkinza/cdk-networkfirewall-l2" /* The "name" in package.json. */,
  peerDeps: ["aws-cdk-lib"],
  projenrcTs: true,
  publishToPypi: {
    distName: "durkinza.cdk-networkfirewall-l2",
    module: "durkinza.cdk_networkfirewall_l2",
  },
  repositoryUrl: "https://github.com/durkinza/cdk-networkfirewall-l2.git",
  eslintOptions: {
    dirs: ["src"],
    devdirs: ["test"],
    prettier: true,
  },
  prettier: true,
});
project.gitignore.exclude("test/**/*.js");
project.gitignore.exclude("test/**/*.d.ts");

new CSpell(project, {
  cSpellOptions: {
    language: "en-US",
    ignorePaths: ["./API.md", "./test/integ.*.expected.json"],
    words: ["projenrc", "ITLS", "devdirs", "certificatemanager"],
  },
});
new Husky(project);
new Commitlint(project);
project.addTask("clean", {
  exec: "yarn exec rimraf dist lib coverage test-reports test-reports",
});

project.synth();
