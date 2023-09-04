import { CfnRuleGroup } from 'aws-cdk-lib/aws-networkfirewall';

/**
 * Cast a string (of) cidr(s) to AddressProperty
 * @param addresses
 */
export function castAddressProperty(addresses:string[]|undefined):CfnRuleGroup.AddressProperty[] {
  let locations:CfnRuleGroup.AddressProperty[] = [];
  if (addresses !== undefined) {
    let address:string;
    for (address of addresses) {
      locations.push({ addressDefinition: address });
    }
  }
  return locations;
}
