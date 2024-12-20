import { CfnTLSInspectionConfiguration, CfnTLSInspectionConfigurationProps } from 'aws-cdk-lib/aws-networkfirewall';
import * as core from 'aws-cdk-lib/core';
import { Construct } from 'constructs';


/**
 * Defines a TLS Inspection Configuration Resource in the stack
 */
export interface ITLSInspectionConfiguration extends core.IResource{
  /**
   * The Arn of the TLS Inspection Configuration.
   * @attribute
   */
  readonly tlsInspectionConfigurationArn: string;

  /**
   * The name of the TLS Inspection Configuration.
   * @attribute
   */
  readonly tlsInspectionConfigurationId: string;

}

/**
 * Defines a Network Firewall TLS Inspection Configuration
 */
abstract class TLSInspectionConfigurationBase extends core.Resource implements ITLSInspectionConfiguration {
  public abstract readonly tlsInspectionConfigurationArn: string;
  public abstract readonly tlsInspectionConfigurationId: string;
}

/**
 * The Properties for defining a Firewall TLS Inspection Configuration
 */
export interface TLSInspectionConfigurationProps {
  /**
   * The descriptive name of the TLS inspection configuration.
   * You can't change the name of a TLS inspection configuration after you create it.
   * @default - CloudFormation-generated name
   */
  readonly configurationName?: string;

  /**
   * The TLS Server Certificate Configuration Property
   */
  readonly serverCertificateConfigurations: CfnTLSInspectionConfiguration.ServerCertificateConfigurationProperty[];

  /**
   * The Description of the TLS Inspection Configuration
   * @default - No Description
   */
  readonly description?: string;

  /**
   * Tags to be added to the configuration.
   * @default - No tags applied
   */
  readonly tags?: core.Tag[];
}

/**
 * Defines a Network Firewall TLS Inspection Configuration in the Stack
 * @resource AWS::NetworkFirewall::TLSInspectionConfiguration
 */
export class TLSInspectionConfiguration extends TLSInspectionConfigurationBase {

  /**
   * Reference an existing TLS Inspection Configuration,
   * defined outside of the CDK code, by name.
   * @param scope
   * @param id
   * @param TLSInspectionConfigurationName
   */
  public static fromConfigurationName(scope: Construct, id: string, TLSInspectionConfigurationName: string): ITLSInspectionConfiguration {
    if (core.Token.isUnresolved(TLSInspectionConfigurationName)) {
      throw new Error('All arguments to TLSInspectionConfiguration.fromConfigurationName must be concrete (no Tokens)');
    }

    /**
     * An ADHOC class for the imported TLS Inspection Configuration.
     */
    class Import extends TLSInspectionConfigurationBase {
      public readonly tlsInspectionConfigurationId = TLSInspectionConfigurationName;
      // Since we have the name, we can generate the ARN,
      public readonly tlsInspectionConfigurationArn = core.Stack.of(scope)
        .formatArn({
          service: 'network-firewall',
          resource: 'tls-configuration',
          resourceName: TLSInspectionConfigurationName,
        });
    }
    return new Import(scope, id);
  }

  /**
   * Reference an existing TLS Inspection Configuration,
   * defined outside of the CDK code, by arn.
   * @param scope
   * @param id
   * @param configurationArn
   */
  public static fromConfigurationArn(scope: Construct, id: string, configurationArn: string): ITLSInspectionConfiguration {
    if (core.Token.isUnresolved(configurationArn)) {
      throw new Error('All arguments to TLSInspectionConfiguration.fromConfigurationArn must be concrete (no Tokens)');
    }
    /**
     * An ADHOC class for the imported TLS Inspection Configuration.
     */
    class Import extends TLSInspectionConfigurationBase {
      public readonly tlsInspectionConfigurationId = core.Fn.select(1, core.Fn.split('/', configurationArn));
      public readonly tlsInspectionConfigurationArn = configurationArn;
    }
    return new Import(scope, id);
  }

  /**
   * The Arn of the TLS Inspection Configuration.
   * @attribute
   */
  public readonly tlsInspectionConfigurationArn: string;

  /**
   * The physical name of the TLS Inspection Configuration.
   * @attribute
   */
  public readonly tlsInspectionConfigurationId: string;

  /**
   * The Description of the TLS Inspection Configuration
   */
  readonly description?: string;

  /**
   * Tags to be added to the TLS Inspection Configuration.
   */
  public readonly tags?: core.Tag[];

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope:Construct, id: string, props: TLSInspectionConfigurationProps) {
    super(scope, id, {
      physicalName: props.configurationName,
    });

    this.description = props.description;
    this.tags = props.tags;

    if (props.serverCertificateConfigurations.length < 1) {
      throw new Error('You must associate at least one certificate configuration to this TLS inspection configuration.');
    }

    const resourceProps:CfnTLSInspectionConfigurationProps = {
      tlsInspectionConfigurationName: props.configurationName||id,
      tlsInspectionConfiguration: { serverCertificateConfigurations: props.serverCertificateConfigurations||[] },
      description: props.description,
      tags: props.tags || [],
    };

    const resource:CfnTLSInspectionConfiguration = new CfnTLSInspectionConfiguration(this, id, resourceProps);

    this.tlsInspectionConfigurationId = this.getResourceNameAttribute(resource.ref);
    this.tlsInspectionConfigurationArn = this.getResourceArnAttribute(resource.attrTlsInspectionConfigurationArn, {
      service: 'network-firewall',
      resource: 'tls-configuration',
      resourceName: this.tlsInspectionConfigurationId,
    });
  }
}