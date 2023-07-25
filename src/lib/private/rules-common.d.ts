import { CfnRuleGroup } from 'aws-cdk-lib/aws-networkfirewall';
/**
 * Cast a string (of) cidr(s) to AddressProperty
 */
export declare function castAddressProperty(addresses: string[] | undefined): CfnRuleGroup.AddressProperty[];
