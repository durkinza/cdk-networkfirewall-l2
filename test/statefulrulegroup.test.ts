import { Template } from 'aws-cdk-lib/assertions';
import * as cdk from 'aws-cdk-lib/core';
import * as NetFW from '../src/lib';

describe('Testing Logging Features', ()=>{
  let stack: cdk.Stack;
  beforeEach(() => {
    // GIVEN
    stack = new cdk.Stack();
  });

  /**
   * Tests for 5 Tuple Stateful rule groups
   */
  test('Default properties on 5Tuple Group', () => {
    // WHEN
    new NetFW.Stateful5TupleRuleGroup(stack, 'MyStateful5TupleRuleGroup');
    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStateful5TupleRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RulesSource: {},
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });

  test('Given properties on 5Tuple Group', () => {
    // GIVEN
    const stateful5TupleRule1 = new NetFW.Stateful5TupleRule({
      action: NetFW.StatefulStandardAction.DROP,
    });
    const stateful5TupleRule2 = new NetFW.Stateful5TupleRule({
      action: NetFW.StatefulStandardAction.PASS,
    });

    // WHEN
    new NetFW.Stateful5TupleRuleGroup(stack, 'MyStateful5TupleRuleGroup', {
      ruleGroupName: 'MyStatefulRuleGroup',
      capacity: 100,
      rules: [stateful5TupleRule1, stateful5TupleRule2],
      variables: {
        ipSets: {
          ipSetsKey: { definition: ['10.0.0.0/16', '10.10.0.0/16'] },
        },
        portSets: {
          portSetsKey: { definition: ['443', '80'] },
        },
      },
      ruleOrder: NetFW.StatefulRuleOptions.STRICT_ORDER,
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStatefulRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RuleVariables: {
          IPSets: {
            ipSetsKey: {
              Definition: ['10.0.0.0/16', '10.10.0.0/16'],
            },
          },
          PortSets: {
            portSetsKey: { Definition: ['443', '80'] },
          },
        },
        RulesSource: {
          StatefulRules: [
            {
              Action: 'DROP',
              Header: {
                Destination: 'ANY',
                DestinationPort: 'ANY',
                Direction: 'ANY',
                Protocol: 'IP',
                Source: 'ANY',
                SourcePort: 'ANY',
              },
              RuleOptions: [],
            },
            {
              Action: 'PASS',
              Header: {
                Destination: 'ANY',
                DestinationPort: 'ANY',
                Direction: 'ANY',
                Protocol: 'IP',
                Source: 'ANY',
                SourcePort: 'ANY',
              },
              RuleOptions: [],
            },
          ],
        },
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });

  /**
   *  Tests Domain List stateful rules
   */

  test('Default properties on Domain List Group', () => {
    // WHEN
    new NetFW.StatefulDomainListRuleGroup(stack, 'MyStatefulDomainListRuleGroup');

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStatefulDomainListRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RulesSource: {},
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });

  test('Given properties on Domain List Group', () => {
    // GIVEN
    const statefulDomainListRule = new NetFW.StatefulDomainListRule({
      type: NetFW.StatefulDomainListType.DENYLIST,
      targets: ['example.com'],
      targetTypes: [NetFW.StatefulDomainListTargetType.HTTP_HOST],
    });

    // WHEN
    new NetFW.StatefulDomainListRuleGroup(stack, 'MyStatefulDomainListRuleGroup', {
      capacity: 100,
      ruleGroupName: 'MyStatefulRuleGroup',
      rule: statefulDomainListRule,
      variables: {
        ipSets: {
          ipSetsKey: { definition: ['10.0.0.0/16', '10.10.0.0/16'] },
        },
        portSets: {
          portSetsKey: { definition: ['443', '80'] },
        },
      },
      ruleOrder: NetFW.StatefulRuleOptions.STRICT_ORDER,
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStatefulRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RuleVariables: {
          IPSets: {
            ipSetsKey: {
              Definition: ['10.0.0.0/16', '10.10.0.0/16'],
            },
          },
          PortSets: {
            portSetsKey: { Definition: ['443', '80'] },
          },
        },
        RulesSource: {
          RulesSourceList: {
            GeneratedRulesType: 'DENYLIST',
            TargetTypes: [
              'HTTP_HOST',
            ],
            Targets: [
              'example.com',
            ],
          },
        },
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });

  /**
   * Tests for Suricata rule groups
   */

  test('Default properties on Suricata Rule Group', () => {
    // WHEN
    new NetFW.StatefulSuricataRuleGroup(stack, 'MyStatefulSuricataRuleGroup');

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStatefulSuricataRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RulesSource: {},
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });

  test('Given properties on Suricata Rule Group', () => {
    // WHEN
    new NetFW.StatefulSuricataRuleGroup(stack, 'MyStatefulSuricataRuleGroup', {
      capacity: 100,
      ruleGroupName: 'MyStatefulRuleGroup',
      rules: 'drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)',
      variables: {
        ipSets: {
          ipSetsKey: { definition: ['10.0.0.0/16', '10.10.0.0/16'] },
        },
        portSets: {
          portSetsKey: { definition: ['443', '80'] },
        },
      },
      ruleOrder: NetFW.StatefulRuleOptions.STRICT_ORDER,
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStatefulRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RuleVariables: {
          IPSets: {
            ipSetsKey: {
              Definition: ['10.0.0.0/16', '10.10.0.0/16'],
            },
          },
          PortSets: {
            portSetsKey: { Definition: ['443', '80'] },
          },
        },
        RulesSource: {
          RulesString: 'drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET TROJAN Likely Bot Nick in IRC (USA +..)\"; flow:established,to_server; flowbits:isset,is_proto_irc; content:\"NICK \"; pcre:\"/NICK .*USA.*[0-9]{3,}/i\"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)',
        },
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });

  test('Can get stateless rule group by name', () => {
    // GIVEN
    const statefulDomainListRuleGroup = NetFW.StatefulDomainListRuleGroup.fromRuleGroupArn(stack, 'MyImportedDomainListRuleGroup', 'arn:aws:networkfirewall:statefulrulegroup');
    const statefulSuricataRuleGroup = NetFW.StatefulSuricataRuleGroup.fromRuleGroupArn(stack, 'MyImportedSuricataRuleGroup', 'arn:aws:networkfirewall:statefulrulegroup');
    const stateful5TupleRuleGroup = NetFW.Stateful5TupleRuleGroup.fromRuleGroupArn(stack, 'MyImportedStateful5TupleRuleGroup', 'arn:aws:networkfirewall:statefulrulegroup');

    // WHEN
    new cdk.CfnResource(stack, 'Res1', {
      type: 'Test::Resource',
      properties: {
        statefulDomainListRuleGroupArn: statefulDomainListRuleGroup.ruleGroupArn,
      },
    });
    new cdk.CfnResource(stack, 'Res2', {
      type: 'Test::Resource',
      properties: {
        statefulSuricataRuleGroupArn: statefulSuricataRuleGroup.ruleGroupArn,
      },
    });
    new cdk.CfnResource(stack, 'Res3', {
      type: 'Test::Resource',
      properties: {
        stateful5TupleRuleGroupArn: stateful5TupleRuleGroup.ruleGroupArn,
      },
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('Test::Resource', {
      statefulDomainListRuleGroupArn: 'arn:aws:networkfirewall:statefulrulegroup',
    });
    Template.fromStack(stack).hasResourceProperties('Test::Resource', {
      statefulSuricataRuleGroupArn: 'arn:aws:networkfirewall:statefulrulegroup',
    });
    Template.fromStack(stack).hasResourceProperties('Test::Resource', {
      stateful5TupleRuleGroupArn: 'arn:aws:networkfirewall:statefulrulegroup',
    });
  });

  test('Can get stateless rule group from file', () => {
    // WHEN
    NetFW.StatefulSuricataRuleGroup.fromFile(stack, 'MyStatefulSuricataRuleGroup', {
      path: './test/suricata.rules',
      capacity: 100,
      ruleGroupName: 'MyStatefulRuleGroup',
      variables: {
        ipSets: {
          ipSetsKey: { definition: ['10.0.0.0/16', '10.10.0.0/16'] },
        },
        portSets: {
          portSetsKey: { definition: ['443', '80'] },
        },
      },
      ruleOrder: NetFW.StatefulRuleOptions.STRICT_ORDER,
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::RuleGroup', {
      Capacity: 100,
      RuleGroupName: 'MyStatefulRuleGroup',
      Type: 'STATEFUL',
      RuleGroup: {
        RuleVariables: {
          IPSets: {
            ipSetsKey: {
              Definition: ['10.0.0.0/16', '10.10.0.0/16'],
            },
          },
          PortSets: {
            portSetsKey: { Definition: ['443', '80'] },
          },
        },
        RulesSource: {
          RulesString: 'drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET TROJAN Likely Bot Nick in IRC (USA +..)\"; flow:established,to_server; flowbits:isset,is_proto_irc; content:\"NICK \"; pcre:\"/NICK .*USA.*[0-9]{3,}/i\"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)',
        },
        StatefulRuleOptions: {
          RuleOrder: 'STRICT_ORDER',
        },
      },
    });
  });
});