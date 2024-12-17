import 'aws-cdk-lib/assertions';
import { castAddressProperty } from '../../src/lib/private/rules-common';

test('castAddressProperty with undefined', () => {
  let j: undefined = undefined;
  expect(castAddressProperty(j)).toStrictEqual([]);
});

test('castAddressProperty with empty array ', () => {
  expect(castAddressProperty([])).toStrictEqual([]);
});

test('castAddressProperty with string array', () => {
  expect(castAddressProperty(['10.0.0.0/24'])).toStrictEqual([{ addressDefinition: '10.0.0.0/24' }]);
});