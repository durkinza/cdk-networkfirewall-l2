"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
//import { Template, Match } from 'aws-cdk-lib/assertions';
const assertions_1 = require("aws-cdk-lib/assertions");
const ec2 = require("aws-cdk-lib/aws-ec2");
const cdk = require("aws-cdk-lib/core");
const NetFW = require("../lib");
test('Default property', () => {
    // GIVEN
    const stack = new cdk.Stack();
    // WHEN
    new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
        statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
        statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
    });
    // THEN
    assertions_1.Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::FirewallPolicy', {
        FirewallPolicy: {
            StatefulRuleGroupReferences: [],
            StatelessDefaultActions: [
                'aws:drop',
            ],
            StatelessFragmentDefaultActions: [
                'aws:drop',
            ],
            StatelessRuleGroupReferences: [],
        },
        FirewallPolicyName: 'MyNetworkFirewallPolicy',
    });
});
test('Can get firewall policy name', () => {
    // GIVEN
    const stack = new cdk.Stack();
    const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
        statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
        statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
    });
    // WHEN
    new cdk.CfnResource(stack, 'Res', {
        type: 'Test::Resource',
        properties: {
            FirewallPolicyName: policy.firewallPolicyId,
        },
    });
    // THEN
    assertions_1.Template.fromStack(stack).hasResourceProperties('Test::Resource', {
        FirewallPolicyName: {
            Ref: 'MyNetworkFirewallPolicy645720A6',
        },
    });
});
test('Can get firewall policy by name', () => {
    // GIVEN
    const stack = new cdk.Stack();
    const policy = NetFW.FirewallPolicy.fromFirewallPolicyName(stack, 'MyNetworkFirewallPolicy', 'MyFirewallPolicy');
    // WHEN
    new cdk.CfnResource(stack, 'Res', {
        type: 'Test::Resource',
        properties: {
            FirewallPolicyName: policy.firewallPolicyId,
        },
    });
    // THEN
    assertions_1.Template.fromStack(stack).hasResourceProperties('Test::Resource', {
        FirewallPolicyName: 'MyFirewallPolicy',
    });
});
test('Policy name must be valid', () => {
    // GIVEN
    const stack = new cdk.Stack();
    // WHEN
    expect(() => {
        new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
            firewallPolicyName: 'MyFirewallPolicy%3',
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
        });
        // THEN
    }).toThrow('firewallPolicyName must contain only letters, numbers, and dashes, got: \'MyFirewallPolicy%3\'');
});
test('Stateless default actions must only have one non-custom action', () => {
    // GIVEN
    const stack = new cdk.Stack();
    // WHEN
    expect(() => {
        new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
            firewallPolicyName: 'MyFirewallPolicy',
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP, NetFW.StatelessStandardAction.PASS],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
        });
        // THEN
    }).toThrow('Only one standard action can be provided for the StatelessDefaultAction, all other actions must be custom');
});
test('Stateless Fragment default actions must only have one non-custom action', () => {
    // GIVEN
    const stack = new cdk.Stack();
    // WHEN
    expect(() => {
        new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
            firewallPolicyName: 'MyFirewallPolicy',
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP, NetFW.StatelessStandardAction.PASS],
        });
        // THEN
    }).toThrow('Only one standard action can be provided for the StatelessFragementDefaultAction, all other actions must be custom');
});
test('Stateful strict actions must only have one non-custom action', () => {
    // GIVEN
    const stack = new cdk.Stack();
    // WHEN
    expect(() => {
        new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
            firewallPolicyName: 'MyFirewallPolicy',
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statefulDefaultActions: [NetFW.StatefulStrictAction.DROP_STRICT, NetFW.StatefulStrictAction.ALERT_STRICT],
        });
        // THEN
    }).toThrow('Only one strict action can be provided for the StatefulDefaultAction, all other actions must be custom');
});
test('Multiple custom default actions can be supplied', () => {
    // GIVEN
    const stack = new cdk.Stack();
    // WHEN
    new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
        firewallPolicyName: 'MyFirewallPolicy',
        statelessDefaultActions: [NetFW.StatelessStandardAction.DROP, 'custom-1', 'custom-2'],
        statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP, 'custom-1', 'custom-2'],
        statefulDefaultActions: [NetFW.StatefulStrictAction.DROP_STRICT, 'custom-1', 'custom-2'],
    });
    // THEN
});
test('verifies unique group priority on stateless rule groups', () => {
    // GIVEN
    const stack = new cdk.Stack();
    const statelessRuleGroup1 = new NetFW.StatelessRuleGroup(stack, 'StatelessRuleGroup1', {
        rules: [],
    });
    const statelessRuleGroup2 = new NetFW.StatelessRuleGroup(stack, 'StatelessRuleGroup2', {
        rules: [],
    });
    const statelessRuleGroupList = [
        {
            priority: 10,
            ruleGroup: statelessRuleGroup1,
        },
        {
            priority: 10,
            ruleGroup: statelessRuleGroup2,
        },
    ];
    expect(() => {
        new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessRuleGroups: statelessRuleGroupList,
        });
        // THEN
    }).toThrow('Priority must be unique, recieved duplicate priority on stateless group');
});
test('verifies unique group priority on stateful groups', () => {
    // GIVEN
    const stack = new cdk.Stack();
    const statefulRuleGroup1 = new NetFW.StatefulSuricataRuleGroup(stack, 'StatefulRuleGroup1', {
        rules: '',
    });
    const statefulRuleGroup2 = new NetFW.StatefulSuricataRuleGroup(stack, 'StatefulRuleGroup2', {
        rules: '',
    });
    const statefulRuleGroupList = [
        {
            priority: 10,
            ruleGroup: statefulRuleGroup1,
        },
        {
            priority: 10,
            ruleGroup: statefulRuleGroup2,
        },
    ];
    expect(() => {
        new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statefulRuleGroups: statefulRuleGroupList,
        });
        // THEN
    }).toThrow('Priority must be unique, recieved duplicate priority on stateful group');
});
test('Can add new groups to policy', () => {
    // GIVEN
    const stack = new cdk.Stack();
    const vpc = new ec2.Vpc(stack, 'MyVpc', {
        ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
    });
    // create some rules
    const statelessRule1 = new NetFW.StatelessRule({
        actions: [NetFW.StatelessStandardAction.FORWARD],
    });
    const statefulRule1 = new NetFW.Stateful5TupleRule({
        action: NetFW.StatefulStandardAction.DROP,
    });
    const statefulRule2 = new NetFW.StatefulDomainListRule({
        type: NetFW.StatefulDomainListType.ALLOWLIST,
        targets: ['example.com'],
        targetTypes: [NetFW.StatefulDomainListTargetType.HTTP_HOST],
    });
    // create some rule groups
    const statelessRuleGroup1 = new NetFW.StatelessRuleGroup(stack, 'StatelessRuleGroup1', {
        rules: [{ rule: statelessRule1, priority: 10 }],
    });
    const statefulRuleGroup1 = new NetFW.Stateful5TupleRuleGroup(stack, 'StatefulRuleGroup1', {
        rules: [statefulRule1],
    });
    const statefulRuleGroup2 = new NetFW.StatefulDomainListRuleGroup(stack, 'StatefulRuleGroup2', {
        rule: statefulRule2,
    });
    const statefulRuleGroup3 = new NetFW.StatefulSuricataRuleGroup(stack, 'StatefulRuleGroup3', {
        rules: '',
    });
    // For stateless rule groups, we must set them into a list
    const statelessRuleGroupList = [
        {
            priority: 10,
            ruleGroup: statelessRuleGroup1,
        },
    ];
    const statefulRuleGroupList = [
        {
            priority: 10,
            ruleGroup: statefulRuleGroup1,
        },
        {
            priority: 20,
            ruleGroup: statefulRuleGroup2,
        },
        {
            priority: 30,
            ruleGroup: statefulRuleGroup3,
        },
    ];
    // WHEN
    const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
        statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
        statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
        statelessRuleGroups: statelessRuleGroupList,
        statefulRuleGroups: statefulRuleGroupList,
    });
    new NetFW.Firewall(stack, 'MyNetworkFirewall20', {
        vpc: vpc,
        policy: policy,
    });
    // THEN
    assertions_1.Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::FirewallPolicy', {
        FirewallPolicyName: 'MyNetworkFirewallPolicy',
        FirewallPolicy: {
            StatefulRuleGroupReferences: [
                {
                    Priority: 10,
                    ResourceArn: {
                        'Fn::GetAtt': [
                            'StatefulRuleGroup185567ABC',
                            'RuleGroupArn',
                        ],
                    },
                },
                {
                    Priority: 20,
                    ResourceArn: {
                        'Fn::GetAtt': [
                            'StatefulRuleGroup2A56B8650',
                            'RuleGroupArn',
                        ],
                    },
                },
                {
                    Priority: 30,
                    ResourceArn: {
                        'Fn::GetAtt': [
                            'StatefulRuleGroup30566741A',
                            'RuleGroupArn',
                        ],
                    },
                },
            ],
            StatelessDefaultActions: [
                'aws:drop',
            ],
            StatelessFragmentDefaultActions: [
                'aws:drop',
            ],
            StatelessRuleGroupReferences: [
                {
                    Priority: 10,
                    ResourceArn: {
                        'Fn::GetAtt': [
                            'StatelessRuleGroup170E51540',
                            'RuleGroupArn',
                        ],
                    },
                },
            ],
        },
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicG9saWN5LnRlc3QuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJwb2xpY3kudGVzdC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLDJEQUEyRDtBQUMzRCx1REFBa0Q7QUFDbEQsMkNBQTJDO0FBQzNDLHdDQUF3QztBQUN4QyxnQ0FBZ0M7QUFFaEMsSUFBSSxDQUFDLGtCQUFrQixFQUFFLEdBQUcsRUFBRTtJQUM1QixRQUFRO0lBQ1IsTUFBTSxLQUFLLEdBQUcsSUFBSSxHQUFHLENBQUMsS0FBSyxFQUFFLENBQUM7SUFDOUIsT0FBTztJQUNQLElBQUksS0FBSyxDQUFDLGNBQWMsQ0FBQyxLQUFLLEVBQUUseUJBQXlCLEVBQUU7UUFDekQsdUJBQXVCLEVBQUUsQ0FBQyxLQUFLLENBQUMsdUJBQXVCLENBQUMsSUFBSSxDQUFDO1FBQzdELCtCQUErQixFQUFFLENBQUMsS0FBSyxDQUFDLHVCQUF1QixDQUFDLElBQUksQ0FBQztLQUN0RSxDQUFDLENBQUM7SUFDSCxPQUFPO0lBQ1AscUJBQVEsQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUMscUJBQXFCLENBQUMsc0NBQXNDLEVBQUU7UUFDdEYsY0FBYyxFQUFFO1lBQ2QsMkJBQTJCLEVBQUUsRUFBRTtZQUMvQix1QkFBdUIsRUFBRTtnQkFDdkIsVUFBVTthQUNYO1lBQ0QsK0JBQStCLEVBQUU7Z0JBQy9CLFVBQVU7YUFDWDtZQUNELDRCQUE0QixFQUFFLEVBQUU7U0FDakM7UUFDRCxrQkFBa0IsRUFBRSx5QkFBeUI7S0FDOUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsOEJBQThCLEVBQUUsR0FBRyxFQUFFO0lBQ3hDLFFBQVE7SUFDUixNQUFNLEtBQUssR0FBRyxJQUFJLEdBQUcsQ0FBQyxLQUFLLEVBQUUsQ0FBQztJQUM5QixNQUFNLE1BQU0sR0FBRyxJQUFJLEtBQUssQ0FBQyxjQUFjLENBQUMsS0FBSyxFQUFFLHlCQUF5QixFQUFFO1FBQ3hF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Y2VzQ29udGVudCI6WyIvL2ltcG9ydCB7IFRlbXBsYXRlLCBNYXRjaCB9IGZyb20gJ2F3cy1jZGstbGliL2Fzc2VydGlvbnMnO1xuaW1wb3J0IHsgVGVtcGxhdGUgfSBmcm9tICdhd3MtY2RrLWxpYi9hc3NlcnRpb25zJztcbmltcG9ydCAqIGFzIGVjMiBmcm9tICdhd3MtY2RrLWxpYi9hd3MtZWMyJztcbmltcG9ydCAqIGFzIGNkayBmcm9tICdhd3MtY2RrLWxpYi9jb3JlJztcbmltcG9ydCAqIGFzIE5ldEZXIGZyb20gJy4uL2xpYic7XG5cbnRlc3QoJ0RlZmF1bHQgcHJvcGVydHknLCAoKSA9PiB7XG4gIC8vIEdJVkVOXG4gIGNvbnN0IHN0YWNrID0gbmV3IGNkay5TdGFjaygpO1xuICAvLyBXSEVOXG4gIG5ldyBOZXRGVy5GaXJld2FsbFBvbGljeShzdGFjaywgJ015TmV0d29ya0ZpcmV3YWxsUG9saWN5Jywge1xuICAgIHN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zOiBbTmV0RlcuU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24uRFJPUF0sXG4gICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICB9KTtcbiAgLy8gVEhFTlxuICBUZW1wbGF0ZS5mcm9tU3RhY2soc3RhY2spLmhhc1Jlc291cmNlUHJvcGVydGllcygnQVdTOjpOZXR3b3JrRmlyZXdhbGw6OkZpcmV3YWxsUG9saWN5Jywge1xuICAgIEZpcmV3YWxsUG9saWN5OiB7XG4gICAgICBTdGF0ZWZ1bFJ1bGVHcm91cFJlZmVyZW5jZXM6IFtdLFxuICAgICAgU3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM6IFtcbiAgICAgICAgJ2F3czpkcm9wJyxcbiAgICAgIF0sXG4gICAgICBTdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zOiBbXG4gICAgICAgICdhd3M6ZHJvcCcsXG4gICAgICBdLFxuICAgICAgU3RhdGVsZXNzUnVsZUdyb3VwUmVmZXJlbmNlczogW10sXG4gICAgfSxcbiAgICBGaXJld2FsbFBvbGljeU5hbWU6ICdNeU5ldHdvcmtGaXJld2FsbFBvbGljeScsXG4gIH0pO1xufSk7XG5cbnRlc3QoJ0NhbiBnZXQgZmlyZXdhbGwgcG9saWN5IG5hbWUnLCAoKSA9PiB7XG4gIC8vIEdJVkVOXG4gIGNvbnN0IHN0YWNrID0gbmV3IGNkay5TdGFjaygpO1xuICBjb25zdCBwb2xpY3kgPSBuZXcgTmV0RlcuRmlyZXdhbGxQb2xpY3koc3RhY2ssICdNeU5ldHdvcmtGaXJld2FsbFBvbGljeScsIHtcbiAgICBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgIHN0YXRlbGVzc0ZyYWdtZW50RGVmYXVsdEFjdGlvbnM6IFtOZXRGVy5TdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbi5EUk9QXSxcbiAgfSk7XG4gIC8vIFdIRU5cbiAgbmV3IGNkay5DZm5SZXNvdXJjZShzdGFjaywgJ1JlcycsIHtcbiAgICB0eXBlOiAnVGVzdDo6UmVzb3VyY2UnLFxuICAgIHByb3BlcnRpZXM6IHtcbiAgICAgIEZpcmV3YWxsUG9saWN5TmFtZTogcG9saWN5LmZpcmV3YWxsUG9saWN5SWQsXG4gICAgfSxcbiAgfSk7XG5cbiAgLy8gVEhFTlxuICBUZW1wbGF0ZS5mcm9tU3RhY2soc3RhY2spLmhhc1Jlc291cmNlUHJvcGVydGllcygnVGVzdDo6UmVzb3VyY2UnLCB7XG4gICAgRmlyZXdhbGxQb2xpY3lOYW1lOiB7XG4gICAgICBSZWY6ICdNeU5ldHdvcmtGaXJld2FsbFBvbGljeTY0NTcyMEE2JyxcbiAgICB9LFxuICB9KTtcbn0pO1xuXG50ZXN0KCdDYW4gZ2V0IGZpcmV3YWxsIHBvbGljeSBieSBuYW1lJywgKCkgPT4ge1xuICAvLyBHSVZFTlxuICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soKTtcbiAgY29uc3QgcG9saWN5ID0gTmV0RlcuRmlyZXdhbGxQb2xpY3kuZnJvbUZpcmV3YWxsUG9saWN5TmFtZShzdGFjaywgJ015TmV0d29ya0ZpcmV3YWxsUG9saWN5JywgJ015RmlyZXdhbGxQb2xpY3knKTtcbiAgLy8gV0hFTlxuICBuZXcgY2RrLkNmblJlc291cmNlKHN0YWNrLCAnUmVzJywge1xuICAgIHR5cGU6ICdUZXN0OjpSZXNvdXJjZScsXG4gICAgcHJvcGVydGllczoge1xuICAgICAgRmlyZXdhbGxQb2xpY3lOYW1lOiBwb2xpY3kuZmlyZXdhbGxQb2xpY3lJZCxcbiAgICB9LFxuICB9KTtcblxuICAvLyBUSEVOXG4gIFRlbXBsYXRlLmZyb21TdGFjayhzdGFjaykuaGFzUmVzb3VyY2VQcm9wZXJ0aWVzKCdUZXN0OjpSZXNvdXJjZScsIHtcbiAgICBGaXJld2FsbFBvbGljeU5hbWU6ICdNeUZpcmV3YWxsUG9saWN5JyxcbiAgfSk7XG59KTtcblxudGVzdCgnUG9saWN5IG5hbWUgbXVzdCBiZSB2YWxpZCcsICgpID0+IHtcbiAgLy8gR0lWRU5cbiAgY29uc3Qgc3RhY2sgPSBuZXcgY2RrLlN0YWNrKCk7XG4gIC8vIFdIRU5cbiAgZXhwZWN0KCgpID0+IHtcbiAgICBuZXcgTmV0RlcuRmlyZXdhbGxQb2xpY3koc3RhY2ssICdNeU5ldHdvcmtGaXJld2FsbFBvbGljeScsIHtcbiAgICAgIGZpcmV3YWxsUG9saWN5TmFtZTogJ015RmlyZXdhbGxQb2xpY3klMycsXG4gICAgICBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgIH0pO1xuICAvLyBUSEVOXG4gIH0pLnRvVGhyb3coJ2ZpcmV3YWxsUG9saWN5TmFtZSBtdXN0IGNvbnRhaW4gb25seSBsZXR0ZXJzLCBudW1iZXJzLCBhbmQgZGFzaGVzLCBnb3Q6IFxcJ015RmlyZXdhbGxQb2xpY3klM1xcJycpO1xufSk7XG5cbnRlc3QoJ1N0YXRlbGVzcyBkZWZhdWx0IGFjdGlvbnMgbXVzdCBvbmx5IGhhdmUgb25lIG5vbi1jdXN0b20gYWN0aW9uJywgKCkgPT4ge1xuICAvLyBHSVZFTlxuICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soKTtcbiAgLy8gV0hFTlxuICBleHBlY3QoKCkgPT4ge1xuICAgIG5ldyBOZXRGVy5GaXJld2FsbFBvbGljeShzdGFjaywgJ015TmV0d29ya0ZpcmV3YWxsUG9saWN5Jywge1xuICAgICAgZmlyZXdhbGxQb2xpY3lOYW1lOiAnTXlGaXJld2FsbFBvbGljeScsXG4gICAgICBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1AsIE5ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLlBBU1NdLFxuICAgICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgIH0pO1xuICAvLyBUSEVOXG4gIH0pLnRvVGhyb3coJ09ubHkgb25lIHN0YW5kYXJkIGFjdGlvbiBjYW4gYmUgcHJvdmlkZWQgZm9yIHRoZSBTdGF0ZWxlc3NEZWZhdWx0QWN0aW9uLCBhbGwgb3RoZXIgYWN0aW9ucyBtdXN0IGJlIGN1c3RvbScpO1xufSk7XG5cbnRlc3QoJ1N0YXRlbGVzcyBGcmFnbWVudCBkZWZhdWx0IGFjdGlvbnMgbXVzdCBvbmx5IGhhdmUgb25lIG5vbi1jdXN0b20gYWN0aW9uJywgKCkgPT4ge1xuICAvLyBHSVZFTlxuICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soKTtcbiAgLy8gV0hFTlxuICBleHBlY3QoKCkgPT4ge1xuICAgIG5ldyBOZXRGVy5GaXJld2FsbFBvbGljeShzdGFjaywgJ015TmV0d29ya0ZpcmV3YWxsUG9saWN5Jywge1xuICAgICAgZmlyZXdhbGxQb2xpY3lOYW1lOiAnTXlGaXJld2FsbFBvbGljeScsXG4gICAgICBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1AsIE5ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLlBBU1NdLFxuICAgIH0pO1xuICAvLyBUSEVOXG4gIH0pLnRvVGhyb3coJ09ubHkgb25lIHN0YW5kYXJkIGFjdGlvbiBjYW4gYmUgcHJvdmlkZWQgZm9yIHRoZSBTdGF0ZWxlc3NGcmFnZW1lbnREZWZhdWx0QWN0aW9uLCBhbGwgb3RoZXIgYWN0aW9ucyBtdXN0IGJlIGN1c3RvbScpO1xufSk7XG5cbnRlc3QoJ1N0YXRlZnVsIHN0cmljdCBhY3Rpb25zIG11c3Qgb25seSBoYXZlIG9uZSBub24tY3VzdG9tIGFjdGlvbicsICgpID0+IHtcbiAgLy8gR0lWRU5cbiAgY29uc3Qgc3RhY2sgPSBuZXcgY2RrLlN0YWNrKCk7XG4gIC8vIFdIRU5cbiAgZXhwZWN0KCgpID0+IHtcbiAgICBuZXcgTmV0RlcuRmlyZXdhbGxQb2xpY3koc3RhY2ssICdNeU5ldHdvcmtGaXJld2FsbFBvbGljeScsIHtcbiAgICAgIGZpcmV3YWxsUG9saWN5TmFtZTogJ015RmlyZXdhbGxQb2xpY3knLFxuICAgICAgc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM6IFtOZXRGVy5TdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbi5EUk9QXSxcbiAgICAgIHN0YXRlbGVzc0ZyYWdtZW50RGVmYXVsdEFjdGlvbnM6IFtOZXRGVy5TdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbi5EUk9QXSxcbiAgICAgIHN0YXRlZnVsRGVmYXVsdEFjdGlvbnM6IFtOZXRGVy5TdGF0ZWZ1bFN0cmljdEFjdGlvbi5EUk9QX1NUUklDVCwgTmV0RlcuU3RhdGVmdWxTdHJpY3RBY3Rpb24uQUxFUlRfU1RSSUNUXSxcbiAgICB9KTtcbiAgLy8gVEhFTlxuICB9KS50b1Rocm93KCdPbmx5IG9uZSBzdHJpY3QgYWN0aW9uIGNhbiBiZSBwcm92aWRlZCBmb3IgdGhlIFN0YXRlZnVsRGVmYXVsdEFjdGlvbiwgYWxsIG90aGVyIGFjdGlvbnMgbXVzdCBiZSBjdXN0b20nKTtcbn0pO1xuXG50ZXN0KCdNdWx0aXBsZSBjdXN0b20gZGVmYXVsdCBhY3Rpb25zIGNhbiBiZSBzdXBwbGllZCcsICgpID0+IHtcbiAgLy8gR0lWRU5cbiAgY29uc3Qgc3RhY2sgPSBuZXcgY2RrLlN0YWNrKCk7XG4gIC8vIFdIRU5cbiAgbmV3IE5ldEZXLkZpcmV3YWxsUG9saWN5KHN0YWNrLCAnTXlOZXR3b3JrRmlyZXdhbGxQb2xpY3knLCB7XG4gICAgZmlyZXdhbGxQb2xpY3lOYW1lOiAnTXlGaXJld2FsbFBvbGljeScsXG4gICAgc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM6IFtOZXRGVy5TdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbi5EUk9QLCAnY3VzdG9tLTEnLCAnY3VzdG9tLTInXSxcbiAgICBzdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zOiBbTmV0RlcuU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24uRFJPUCwgJ2N1c3RvbS0xJywgJ2N1c3RvbS0yJ10sXG4gICAgc3RhdGVmdWxEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlZnVsU3RyaWN0QWN0aW9uLkRST1BfU1RSSUNULCAnY3VzdG9tLTEnLCAnY3VzdG9tLTInXSxcbiAgfSk7XG4gIC8vIFRIRU5cbn0pO1xuXG50ZXN0KCd2ZXJpZmllcyB1bmlxdWUgZ3JvdXAgcHJpb3JpdHkgb24gc3RhdGVsZXNzIHJ1bGUgZ3JvdXBzJywgKCkgPT4ge1xuICAvLyBHSVZFTlxuICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soKTtcbiAgY29uc3Qgc3RhdGVsZXNzUnVsZUdyb3VwMSA9IG5ldyBOZXRGVy5TdGF0ZWxlc3NSdWxlR3JvdXAoc3RhY2ssICdTdGF0ZWxlc3NSdWxlR3JvdXAxJywge1xuICAgIHJ1bGVzOiBbXSxcbiAgfSk7XG4gIGNvbnN0IHN0YXRlbGVzc1J1bGVHcm91cDIgPSBuZXcgTmV0RlcuU3RhdGVsZXNzUnVsZUdyb3VwKHN0YWNrLCAnU3RhdGVsZXNzUnVsZUdyb3VwMicsIHtcbiAgICBydWxlczogW10sXG4gIH0pO1xuXG4gIGNvbnN0IHN0YXRlbGVzc1J1bGVHcm91cExpc3Q6TmV0RlcuU3RhdGVsZXNzUnVsZUdyb3VwTGlzdFtdID0gW1xuICAgIHtcbiAgICAgIHByaW9yaXR5OiAxMCxcbiAgICAgIHJ1bGVHcm91cDogc3RhdGVsZXNzUnVsZUdyb3VwMSxcbiAgICB9LFxuICAgIHtcbiAgICAgIHByaW9yaXR5OiAxMCxcbiAgICAgIHJ1bGVHcm91cDogc3RhdGVsZXNzUnVsZUdyb3VwMixcbiAgICB9LFxuICBdO1xuXG4gIGV4cGVjdCgoKSA9PiB7XG4gICAgbmV3IE5ldEZXLkZpcmV3YWxsUG9saWN5KHN0YWNrLCAnTXlOZXR3b3JrRmlyZXdhbGxQb2xpY3knLCB7XG4gICAgICBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgc3RhdGVsZXNzUnVsZUdyb3Vwczogc3RhdGVsZXNzUnVsZUdyb3VwTGlzdCxcbiAgICB9KTtcbiAgLy8gVEhFTlxuICB9KS50b1Rocm93KCdQcmlvcml0eSBtdXN0IGJlIHVuaXF1ZSwgcmVjaWV2ZWQgZHVwbGljYXRlIHByaW9yaXR5IG9uIHN0YXRlbGVzcyBncm91cCcpO1xufSk7XG5cbnRlc3QoJ3ZlcmlmaWVzIHVuaXF1ZSBncm91cCBwcmlvcml0eSBvbiBzdGF0ZWZ1bCBncm91cHMnLCAoKSA9PiB7XG4gIC8vIEdJVkVOXG4gIGNvbnN0IHN0YWNrID0gbmV3IGNkay5TdGFjaygpO1xuICBjb25zdCBzdGF0ZWZ1bFJ1bGVHcm91cDEgPSBuZXcgTmV0RlcuU3RhdGVmdWxTdXJpY2F0YVJ1bGVHcm91cChzdGFjaywgJ1N0YXRlZnVsUnVsZUdyb3VwMScsIHtcbiAgICBydWxlczogJycsXG4gIH0pO1xuICBjb25zdCBzdGF0ZWZ1bFJ1bGVHcm91cDIgPSBuZXcgTmV0RlcuU3RhdGVmdWxTdXJpY2F0YVJ1bGVHcm91cChzdGFjaywgJ1N0YXRlZnVsUnVsZUdyb3VwMicsIHtcbiAgICBydWxlczogJycsXG4gIH0pO1xuXG4gIGNvbnN0IHN0YXRlZnVsUnVsZUdyb3VwTGlzdDpOZXRGVy5TdGF0ZWZ1bFJ1bGVHcm91cExpc3RbXSA9IFtcbiAgICB7XG4gICAgICBwcmlvcml0eTogMTAsXG4gICAgICBydWxlR3JvdXA6IHN0YXRlZnVsUnVsZUdyb3VwMSxcbiAgICB9LFxuICAgIHtcbiAgICAgIHByaW9yaXR5OiAxMCxcbiAgICAgIHJ1bGVHcm91cDogc3RhdGVmdWxSdWxlR3JvdXAyLFxuICAgIH0sXG4gIF07XG5cbiAgZXhwZWN0KCgpID0+IHtcbiAgICBuZXcgTmV0RlcuRmlyZXdhbGxQb2xpY3koc3RhY2ssICdNeU5ldHdvcmtGaXJld2FsbFBvbGljeScsIHtcbiAgICAgIHN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zOiBbTmV0RlcuU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24uRFJPUF0sXG4gICAgICBzdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zOiBbTmV0RlcuU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24uRFJPUF0sXG4gICAgICBzdGF0ZWZ1bFJ1bGVHcm91cHM6IHN0YXRlZnVsUnVsZUdyb3VwTGlzdCxcbiAgICB9KTtcbiAgLy8gVEhFTlxuICB9KS50b1Rocm93KCdQcmlvcml0eSBtdXN0IGJlIHVuaXF1ZSwgcmVjaWV2ZWQgZHVwbGljYXRlIHByaW9yaXR5IG9uIHN0YXRlZnVsIGdyb3VwJyk7XG59KTtcblxudGVzdCgnQ2FuIGFkZCBuZXcgZ3JvdXBzIHRvIHBvbGljeScsICgpID0+IHtcbiAgLy8gR0lWRU5cbiAgY29uc3Qgc3RhY2sgPSBuZXcgY2RrLlN0YWNrKCk7XG4gIGNvbnN0IHZwYyA9IG5ldyBlYzIuVnBjKHN0YWNrLCAnTXlWcGMnLCB7XG4gICAgaXBBZGRyZXNzZXM6IGVjMi5JcEFkZHJlc3Nlcy5jaWRyKCcxMC4wLjAuMC8xNicpLFxuICB9KTtcbiAgLy8gY3JlYXRlIHNvbWUgcnVsZXNcbiAgY29uc3Qgc3RhdGVsZXNzUnVsZTEgPSBuZXcgTmV0RlcuU3RhdGVsZXNzUnVsZSh7XG4gICAgYWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkZPUldBUkRdLFxuICB9KTtcbiAgY29uc3Qgc3RhdGVmdWxSdWxlMSA9IG5ldyBOZXRGVy5TdGF0ZWZ1bDVUdXBsZVJ1bGUoe1xuICAgIGFjdGlvbjogTmV0RlcuU3RhdGVmdWxTdGFuZGFyZEFjdGlvbi5EUk9QLFxuICB9KTtcbiAgY29uc3Qgc3RhdGVmdWxSdWxlMiA9IG5ldyBOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RSdWxlKHtcbiAgICB0eXBlOiBOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RUeXBlLkFMTE9XTElTVCxcbiAgICB0YXJnZXRzOiBbJ2V4YW1wbGUuY29tJ10sXG4gICAgdGFyZ2V0VHlwZXM6IFtOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RUYXJnZXRUeXBlLkhUVFBfSE9TVF0sXG4gIH0pO1xuICAvLyBjcmVhdGUgc29tZSBydWxlIGdyb3Vwc1xuICBjb25zdCBzdGF0ZWxlc3NSdWxlR3JvdXAxID0gbmV3IE5ldEZXLlN0YXRlbGVzc1J1bGVHcm91cChzdGFjaywgJ1N0YXRlbGVzc1J1bGVHcm91cDEnLCB7XG4gICAgcnVsZXM6IFt7IHJ1bGU6IHN0YXRlbGVzc1J1bGUxLCBwcmlvcml0eTogMTAgfV0sXG4gIH0pO1xuICBjb25zdCBzdGF0ZWZ1bFJ1bGVHcm91cDEgPSBuZXcgTmV0RlcuU3RhdGVmdWw1VHVwbGVSdWxlR3JvdXAoc3RhY2ssICdTdGF0ZWZ1bFJ1bGVHcm91cDEnLCB7XG4gICAgcnVsZXM6IFtzdGF0ZWZ1bFJ1bGUxXSxcbiAgfSk7XG4gIGNvbnN0IHN0YXRlZnVsUnVsZUdyb3VwMiA9IG5ldyBOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RSdWxlR3JvdXAoc3RhY2ssICdTdGF0ZWZ1bFJ1bGVHcm91cDInLCB7XG4gICAgcnVsZTogc3RhdGVmdWxSdWxlMixcbiAgfSk7XG4gIGNvbnN0IHN0YXRlZnVsUnVsZUdyb3VwMyA9IG5ldyBOZXRGVy5TdGF0ZWZ1bFN1cmljYXRhUnVsZUdyb3VwKHN0YWNrLCAnU3RhdGVmdWxSdWxlR3JvdXAzJywge1xuICAgIHJ1bGVzOiAnJyxcbiAgfSk7XG5cbiAgLy8gRm9yIHN0YXRlbGVzcyBydWxlIGdyb3Vwcywgd2UgbXVzdCBzZXQgdGhlbSBpbnRvIGEgbGlzdFxuICBjb25zdCBzdGF0ZWxlc3NSdWxlR3JvdXBMaXN0Ok5ldEZXLlN0YXRlbGVzc1J1bGVHcm91cExpc3RbXSA9IFtcbiAgICB7XG4gICAgICBwcmlvcml0eTogMTAsXG4gICAgICBydWxlR3JvdXA6IHN0YXRlbGVzc1J1bGVHcm91cDEsXG4gICAgfSxcbiAgXTtcbiAgY29uc3Qgc3RhdGVmdWxSdWxlR3JvdXBMaXN0Ok5ldEZXLlN0YXRlZnVsUnVsZUdyb3VwTGlzdFtdID0gW1xuICAgIHtcbiAgICAgIHByaW9yaXR5OiAxMCxcbiAgICAgIHJ1bGVHcm91cDogc3RhdGVmdWxSdWxlR3JvdXAxLFxuICAgIH0sXG4gICAge1xuICAgICAgcHJpb3JpdHk6IDIwLFxuICAgICAgcnVsZUdyb3VwOiBzdGF0ZWZ1bFJ1bGVHcm91cDIsXG4gICAgfSxcbiAgICB7XG4gICAgICBwcmlvcml0eTogMzAsXG4gICAgICBydWxlR3JvdXA6IHN0YXRlZnVsUnVsZUdyb3VwMyxcbiAgICB9LFxuICBdO1xuICAvLyBXSEVOXG4gIGNvbnN0IHBvbGljeSA9IG5ldyBOZXRGVy5GaXJld2FsbFBvbGljeShzdGFjaywgJ015TmV0d29ya0ZpcmV3YWxsUG9saWN5Jywge1xuICAgIHN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zOiBbTmV0RlcuU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24uRFJPUF0sXG4gICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgIHN0YXRlbGVzc1J1bGVHcm91cHM6IHN0YXRlbGVzc1J1bGVHcm91cExpc3QsXG4gICAgc3RhdGVmdWxSdWxlR3JvdXBzOiBzdGF0ZWZ1bFJ1bGVHcm91cExpc3QsXG4gIH0pO1xuICBuZXcgTmV0RlcuRmlyZXdhbGwoc3RhY2ssICdNeU5ldHdvcmtGaXJld2FsbDIwJywge1xuICAgIHZwYzogdnBjLFxuICAgIHBvbGljeTogcG9saWN5LFxuICB9KTtcbiAgLy8gVEhFTlxuICBUZW1wbGF0ZS5mcm9tU3RhY2soc3RhY2spLmhhc1Jlc291cmNlUHJvcGVydGllcygnQVdTOjpOZXR3b3JrRmlyZXdhbGw6OkZpcmV3YWxsUG9saWN5Jywge1xuICAgIEZpcmV3YWxsUG9saWN5TmFtZTogJ015TmV0d29ya0ZpcmV3YWxsUG9saWN5JyxcbiAgICBGaXJld2FsbFBvbGljeToge1xuICAgICAgU3RhdGVmdWxSdWxlR3JvdXBSZWZlcmVuY2VzOiBbXG4gICAgICAgIHtcbiAgICAgICAgICBQcmlvcml0eTogMTAsXG4gICAgICAgICAgUmVzb3VyY2VBcm46IHtcbiAgICAgICAgICAgICdGbjo6R2V0QXR0JzogW1xuICAgICAgICAgICAgICAnU3RhdGVmdWxSdWxlR3JvdXAxODU1NjdBQkMnLFxuICAgICAgICAgICAgICAnUnVsZUdyb3VwQXJuJyxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIFByaW9yaXR5OiAyMCxcbiAgICAgICAgICBSZXNvdXJjZUFybjoge1xuICAgICAgICAgICAgJ0ZuOjpHZXRBdHQnOiBbXG4gICAgICAgICAgICAgICdTdGF0ZWZ1bFJ1bGVHcm91cDJBNTZCODY1MCcsXG4gICAgICAgICAgICAgICdSdWxlR3JvdXBBcm4nLFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgUHJpb3JpdHk6IDMwLFxuICAgICAgICAgIFJlc291cmNlQXJuOiB7XG4gICAgICAgICAgICAnRm46OkdldEF0dCc6IFtcbiAgICAgICAgICAgICAgJ1N0YXRlZnVsUnVsZUdyb3VwMzA1NjY3NDFBJyxcbiAgICAgICAgICAgICAgJ1J1bGVHcm91cEFybicsXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICBdLFxuICAgICAgU3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM6IFtcbiAgICAgICAgJ2F3czpkcm9wJyxcbiAgICAgIF0sXG4gICAgICBTdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zOiBbXG4gICAgICAgICdhd3M6ZHJvcCcsXG4gICAgICBdLFxuICAgICAgU3RhdGVsZXNzUnVsZUdyb3VwUmVmZXJlbmNlczogW1xuICAgICAgICB7XG4gICAgICAgICAgUHJpb3JpdHk6IDEwLFxuICAgICAgICAgIFJlc291cmNlQXJuOiB7XG4gICAgICAgICAgICAnRm46OkdldEF0dCc6IFtcbiAgICAgICAgICAgICAgJ1N0YXRlbGVzc1J1bGVHcm91cDE3MEU1MTU0MCcsXG4gICAgICAgICAgICAgICdSdWxlR3JvdXBBcm4nLFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9LFxuICB9KTtcbn0pO1xuIl19