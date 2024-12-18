//import { Template, Match } from 'aws-cdk-lib/assertions';
import { Template } from 'aws-cdk-lib/assertions';
import * as cdk from 'aws-cdk-lib/core';
import * as NetFW from '../src/lib';

describe('Testing TLS Inspection Features', ()=>{
  let stack: cdk.Stack;
  beforeEach(() => {
    // GIVEN
    stack = new cdk.Stack();
  });

  test('Default Setup', () => {
    // WHEN
    new NetFW.TLSInspectionConfiguration(stack, 'MyTLSInspectionConfiguration', {
      tags: [new cdk.Tag('test', 'test')],
      serverCertificateConfigurations: [{
        certificateAuthorityArn: 'certificateAuthorityArn',
        checkCertificateRevocationStatus: {
          revokedStatusAction: 'revokedStatusAction',
          unknownStatusAction: 'unknownStatusAction',
        },
        scopes: [{
          destinationPorts: [{
            fromPort: 123,
            toPort: 123,
          }],
          destinations: [{
            addressDefinition: 'addressDefinition',
          }],
          protocols: [123],
          sourcePorts: [{
            fromPort: 123,
            toPort: 123,
          }],
          sources: [{
            addressDefinition: 'addressDefinition',
          }],
        }],
        serverCertificates: [{
          resourceArn: 'resourceArn',
        }],
      }],
    });


    console.log(Template.fromStack(stack).toJSON().Resources.MyTLSInspectionConfigurationDE9CA174.Properties);
    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::TLSInspectionConfiguration', {
      TLSInspectionConfigurationName: 'MyTLSInspectionConfiguration',
      Tags: [{ Key: 'test', Value: 'test' }],
      TLSInspectionConfiguration: {
        ServerCertificateConfigurations: [{}],
      },
    });
  });

  test('Default Setup', () => {
    // WHEN
    expect(() => {
      new NetFW.TLSInspectionConfiguration(stack, 'MyTLSInspectionConfiguration', {
        serverCertificateConfigurations: [],
      });
    }).toThrow('You must associate at least one certificate configuration to this TLS inspection configuration.');
  });
});