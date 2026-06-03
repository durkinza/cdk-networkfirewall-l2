// Not yet supported in CDK L1 at time of writing.
// Ref: https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_EncryptionConfiguration.html
export enum EncryptionConfigurationTypes {
  CUSTOMER_KMS = "CUSTOMER_KMS",
  AWS_OWNED_KMS_KEY = "AWS_OWNED_KMS_KEY",
}

export interface EncryptionConfiguration {
  readonly type: EncryptionConfigurationTypes;
  /**
   * The ID of the customer managed key.
   * Required when type is CUSTOMER_KMS, not needed for AWS_OWNED_KMS_KEY.
   */
  readonly keyId?: string;
}
