import { Construct } from 'constructs';
import { CfnRuleGroup } from 'aws-cdk-lib/aws-networkfirewall';
import { StatelessRule, Stateful5TupleRule, StatefulDomainListRule } from './rule';
import * as core from 'aws-cdk-lib/core';
/**
 * Maps a priority to a stateless rule
 */
export interface StatelessRuleList {
    /**
     * The priority of the rule in the rule group
     */
    readonly priority: number;
    /**
     * The stateless rule
     */
    readonly rule: StatelessRule;
}
/**
 * Defines a Stateless rule Group in the stack
 */
export interface IStatelessRuleGroup extends core.IResource {
    /**
       * The Arn of the rule group
       *
       * @attribute
       */
    readonly ruleGroupArn: string;
    /**
       * the physical name of the rule group
       *
       * @attribute
       */
    readonly ruleGroupId: string;
}
/**
 * The Base class for Stateless Rule Groups
 */
declare abstract class StatelessRuleGroupBase extends core.Resource implements IStatelessRuleGroup {
    abstract readonly ruleGroupArn: string;
    abstract readonly ruleGroupId: string;
}
/**
 * The properties for defining a Stateless Rule Group
 */
export interface StatelessRuleGroupProps {
    /**
       * The descriptive name of the stateless rule group
       *
       * @default - CloudFormation-generated name
       */
    readonly ruleGroupName?: string;
    /**
       * The maximum operating resources that this rule group can use.
       *
       * @default - Capacity is Calculated from rule requirements.
       */
    readonly capacity?: number;
    /**
       * The rule group rules
       *
       * @default = undefined
       */
    readonly rules?: StatelessRuleList[];
    /**
       * An optional Non-standard action to use
       *
       * @default - undefined
       */
    readonly customActions?: CfnRuleGroup.CustomActionProperty[];
    /**
     * Settings that are available for use in the rules
     *
     * @default - undefined
     */
    readonly variables?: CfnRuleGroup.RuleVariablesProperty;
    /**
     * Description of the rule group
     *
     * @default - undefined
     */
    readonly description?: string;
}
/**
 * A Stateless Rule group that holds Stateless Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export declare class StatelessRuleGroup extends StatelessRuleGroupBase {
    /**
     * Refernce existing Rule Group by Name
     */
    static fromStatelessRuleGroupName(scope: Construct, id: string, statelessRuleGroupName: string): IStatelessRuleGroup;
    /**
     * Reference existing Rule Group by Arn
     */
    static fromStatelessRuleGroupArn(scope: Construct, id: string, statelessRuleGroupArn: string): IStatelessRuleGroup;
    readonly ruleGroupId: string;
    readonly ruleGroupArn: string;
    private rules;
    constructor(scope: Construct, id: string, props?: StatelessRuleGroupProps);
    /**
     * Calculates the expected capacity required for all applied stateful rules.
     */
    calculateCapacity(): number;
    /**
     * Ensure all priorities are within allowed range values
     */
    private verifyPriorities;
}
/**
 * The Interface that represents a Stateful Rule Group
 */
export interface IStatefulRuleGroup extends core.IResource {
    /**
     * The Arn of the rule group
     *
     * @attribute
     */
    readonly ruleGroupArn: string;
    /**
     * the physical name of the rule group
     *
     * @attribute
     */
    readonly ruleGroupId: string;
}
/**
 * Indicates how to manage the order of the rule evaluation for the rule group.
 */
export declare enum StatefulRuleOptions {
    /**
     * This is the default action
     * Stateful rules are provided to the rule engine as Suricata compatible strings, and Suricata evaluates them based on certain settings
     */
    DEFAULT_ACTION_ORDER = "DEFAULT_ACTION_ORDER",
    /**
     * With strict ordering, the rule groups are evaluated by order of priority, starting from the lowest number, and the rules in each rule group are processed in the order in which they're defined.
     */
    STRICT_ORDER = "STRICT_ORDER"
}
/**
 * Properties for defining a Stateful Rule Group
 */
interface StatefulRuleGroupProps {
    /**
     * The descriptive name of the stateful rule group
     *
     * @default - CloudFormation-generated name
     */
    readonly ruleGroupName?: string;
    /**
     * The maximum operating resources that this rule group can use.
     * Estimate a stateful rule group's capacity as the number of rules that you expect to have in it during its lifetime.
     * You can't change this setting after you create the rule group
     * @default - 200
     */
    readonly capacity?: number;
    /**
     * Settings that are available for use in the rules
     *
     * @default - undefined
     */
    readonly variables?: CfnRuleGroup.RuleVariablesProperty;
    /**
     * Rule Order
     *
     * @default - DEFAULT_RULE_ACTION_ORDER
     */
    readonly ruleOrder?: StatefulRuleOptions;
    /**
     * Description of the rule group
     *
     * @default - undefined
     */
    readonly description?: string;
}
/**
 * Defines a Stateful Rule Group in the stack
 */
declare abstract class StatefulRuleGroup extends core.Resource implements IStatefulRuleGroup {
    /**
     * Reference existing Rule Group
     */
    static fromRuleGroupArn(scope: Construct, id: string, ruleGroupArn: string): IStatefulRuleGroup;
    abstract readonly ruleGroupArn: string;
    abstract readonly ruleGroupId: string;
    constructor(scope: Construct, id: string, props?: StatefulRuleGroupProps);
}
/**
 * Properties for defining a Stateful Suricata Rule Group
 *
 * @resource AWS::NetworkFIrewall::RuleGroup
 */
export interface StatefulSuricataRuleGroupProps extends StatefulRuleGroupProps {
    /**
     * The suricata rules
     *
     * @default - undefined
     */
    readonly rules?: string;
}
/**
 * A Stateful Rule group that holds Suricata Rules
 *
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export declare class StatefulSuricataRuleGroup extends StatefulRuleGroup {
    readonly ruleGroupArn: string;
    readonly ruleGroupId: string;
    constructor(scope: Construct, id: string, props?: StatefulSuricataRuleGroupProps);
}
/**
 * Properties for defining a Stateful 5 Tuple Rule Group
 *
 * @resource AWS::NetworkFIrewall::RuleGroup
 */
export interface Stateful5TupleRuleGroupProps extends StatefulRuleGroupProps {
    /**
     * The rule group rules
     *
     * @default - undefined
     */
    readonly rules?: Stateful5TupleRule[];
}
/**
 * A Stateful Rule group that holds 5Tuple Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export declare class Stateful5TupleRuleGroup extends StatefulRuleGroup {
    readonly ruleGroupArn: string;
    readonly ruleGroupId: string;
    constructor(scope: Construct, id: string, props?: Stateful5TupleRuleGroupProps);
}
/**
 * Defines a Stateful Domain List Rule group in the stack
 *
 * @resource AWS::NetworkFIrewall::RuleGroup
 */
export interface StatefulDomainListRuleGroupProps extends StatefulRuleGroupProps {
    /**
     * The Domain List rule
     * @default - undefined
     */
    readonly rule?: StatefulDomainListRule;
}
/**
 * A Stateful Rule group that holds Domain List Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export declare class StatefulDomainListRuleGroup extends StatefulRuleGroup {
    readonly ruleGroupArn: string;
    readonly ruleGroupId: string;
    constructor(scope: Construct, id: string, props?: StatefulDomainListRuleGroupProps);
}
export {};
