// Ref: https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_EncryptionConfiguration.html
export enum EncryptionConfigurationTypes {
  CUSTOMER_KMS = 'CUSTOMER_KMS',
  AWS_OWNED_KMS_KEY = 'AWS_OWNED_KMS_KEY'
}

export interface EncryptionConfiguration {
  readonly type: EncryptionConfigurationTypes;
  readonly keyId: string;
}