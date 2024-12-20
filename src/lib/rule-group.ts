import { readFileSync } from 'fs';
import { CfnRuleGroup, CfnRuleGroupProps } from 'aws-cdk-lib/aws-networkfirewall';
import * as core from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import { StatelessRule, Stateful5TupleRule, StatefulDomainListRule } from './rule';

//import { StatelessStandardAction, StatefulStandardAction } from './actions';

/**
 * Maps a priority to a stateless rule
 */
export interface StatelessRuleList{
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
 * The Possible Rule Group Types
 */
enum RuleGroupType {
  /**
   * For Stateless Rule Group Types
   */
  STATELESS = 'STATELESS',

  /**
   * For Stateful Rule Group Types
   */
  STATEFUL = 'STATEFUL',
}

/**
 * Defines a Stateless rule Group in the stack
 */
export interface IStatelessRuleGroup extends core.IResource {
  /**
   * The Arn of the rule group
   * @attribute
   */
  readonly ruleGroupArn: string;

  /**
   * the physical name of the rule group
   * @attribute
   */
  readonly ruleGroupId: string;
}

/**
 * The Base class for Stateless Rule Groups
 */
abstract class StatelessRuleGroupBase extends core.Resource implements IStatelessRuleGroup {
  public abstract readonly ruleGroupArn: string;
  public abstract readonly ruleGroupId: string;
}

/**
 * The properties for defining a Stateless Rule Group
 */
export interface StatelessRuleGroupProps {
  /**
   * The descriptive name of the stateless rule group
   * @default - CloudFormation-generated name
   */
  readonly ruleGroupName?: string;
  /**
   * The maximum operating resources that this rule group can use.
   * @default - Capacity is Calculated from rule requirements.
   */
  readonly capacity?: number;

  /**
   * The rule group rules
   * @default - undefined
   */
  readonly rules?: StatelessRuleList[];

  /**
   * An optional Non-standard action to use
   * @default - undefined
   */
  readonly customActions?: CfnRuleGroup.CustomActionProperty[];

  /**
   * Settings that are available for use in the rules
   * @default - undefined
   */
  readonly variables?: CfnRuleGroup.RuleVariablesProperty;

  /**
   * Description of the rule group
   * @default - undefined
   */
  readonly description?: string;
}

/**
 * A Stateless Rule group that holds Stateless Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export class StatelessRuleGroup extends StatelessRuleGroupBase {
  /**
   * Reference existing Rule Group by Name
   * @param scope
   * @param id
   * @param statelessRuleGroupName
   */
  public static fromStatelessRuleGroupName(scope: Construct, id: string, statelessRuleGroupName: string): IStatelessRuleGroup {
    /**
     *
     */
    class Import extends StatelessRuleGroupBase {
      public readonly ruleGroupId = statelessRuleGroupName;
      public readonly ruleGroupArn = core.Stack.of(scope).formatArn({
        service: 'network-firewall',
        resource: 'stateless-rulegroup',
        resourceName: statelessRuleGroupName,
      });
    }
    return new Import(scope, id);
  }

  /**
   * Reference existing Rule Group by Arn
   * @param scope
   * @param id
   * @param statelessRuleGroupArn
   */
  public static fromStatelessRuleGroupArn(scope: Construct, id: string, statelessRuleGroupArn: string): IStatelessRuleGroup {
    /**
     *
     */
    class Import extends StatelessRuleGroupBase {
      public readonly ruleGroupId = core.Fn.select(1, core.Fn.split('/', statelessRuleGroupArn));
      public readonly ruleGroupArn = statelessRuleGroupArn;
    }
    return new Import(scope, id);
  }

  public readonly ruleGroupId: string;
  public readonly ruleGroupArn: string;
  private rules:StatelessRuleList[];

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope: Construct, id:string, props?: StatelessRuleGroupProps) {
    if (props === undefined) {props = {};}
    super(scope, id, {
      physicalName: props.ruleGroupName,
    });

    // Adding Validations

    /**
     * Validate ruleGroupId
     */
    if (props.ruleGroupName !== undefined &&
				!/^[\dA-Za-z-]+$/.test(props.ruleGroupName)) {
      throw new Error('ruleGroupName must be non-empty and contain only letters, numbers, and dashes, ' +
				`got: '${props.ruleGroupName}'`);
    }

    /**
     * Validate Rule priority
     */
    this.rules = props.rules||[];
    this.verifyPriorities();
    /**
     * Validating Capacity
     */
    const capacity:number = props.capacity || this.calculateCapacity();
    if (!Number.isInteger(capacity)) {
      throw new TypeError('Capacity must be an integer value, '+
				`got: '${capacity}'`);
    }
    if (capacity < 0 || capacity > 30000) {
      throw new Error('Capacity must be a positive value less than 30,000, '+
				`got: '${capacity}'`);
    }

    const statelessRules:CfnRuleGroup.StatelessRuleProperty[] = [];
    if (props.rules !== undefined) {
      let rule:StatelessRuleList;
      for (rule of props.rules) {
        statelessRules.push(
          <CfnRuleGroup.StatelessRuleProperty>{
            ruleDefinition: rule.rule.resource,
            priority: rule.priority,
          },
        );
      }
    }

    const statelessRulesAndCustomActions:CfnRuleGroup.StatelessRulesAndCustomActionsProperty={
      statelessRules: statelessRules,
      customActions: props.customActions,
    };

    const resourceRulesSource:CfnRuleGroup.RulesSourceProperty = {
      statelessRulesAndCustomActions: statelessRulesAndCustomActions,
    };

    //const resourceVariables:CfnRuleGroup.RuleVariablesProperty = props.variables;

    const resourceRuleGroupProperty:CfnRuleGroup.RuleGroupProperty={
      rulesSource: resourceRulesSource,
      ruleVariables: props.variables,
    };

    const resourceProps:CfnRuleGroupProps={
      capacity: capacity,
      ruleGroupName: props.ruleGroupName || id,
      type: RuleGroupType.STATELESS,
      ruleGroup: resourceRuleGroupProperty,
      description: props.description,
      //tags
    };
    const resource:CfnRuleGroup = new CfnRuleGroup(this, id, resourceProps);
    this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
    this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
      service: 'network-firewall',
      resource: 'stateless-rulegroup',
      resourceName: this.ruleGroupId,
    });
  }

  /**
   * Calculates the expected capacity required for all applied stateful rules.
   */
  public calculateCapacity(): number {
    let total:number = 0;
    var statelessRule: StatelessRuleList;
    if (this.rules !== undefined) {
      for (statelessRule of this.rules) {
        total += statelessRule.rule.calculateCapacity();
      }
    }
    return total;
  }

  /**
   * Ensure all priorities are within allowed range values
   */
  private verifyPriorities() {
    let priorities:number[] = [];
    let rule:StatelessRuleList;
    for (rule of this.rules) {
      if (priorities.includes(rule.priority)) {
        throw new Error('Priority must be unique, '+
          `got duplicate priority: '${rule.priority}'`);
      }
      if (rule.priority < 0 || rule.priority > 30000) {
        throw new Error('Priority must be a positive value less than 30000'+
          `got: '${rule.priority}'`);
      }
      priorities.push(rule.priority);
    }
  }
}

//
//  Define Stateful Rule Groups
//

/**
 * The Interface that represents a Stateful Rule Group
 */
export interface IStatefulRuleGroup extends core.IResource {
  /**
   * The Arn of the rule group
   * @attribute
   */
  readonly ruleGroupArn: string;

  /**
   * the physical name of the rule group
   * @attribute
   */
  readonly ruleGroupId: string;
}

/**
 * Indicates how to manage the order of the rule evaluation for the rule group.
 */
export enum StatefulRuleOptions {
  /**
   * Rules with a pass action are processed first, followed by drop, reject, and alert actions.
   * This option was previously named Default Acton Order.
   */
  ACTION_ORDER='DEFAULT_ACTION_ORDER',

  /**
   * Rules with a pass action are processed first, followed by drop, reject, and alert actions.
   * @deprecated Please use ACTION_ORDER instead.
   */
  // DEFAULT_ACTION_ORDER='DEFAULT_ACTION_ORDER',

  /**
   * With strict ordering, the rule groups are evaluated by order of priority, starting from the lowest number, and the rules in each rule group are processed in the order in which they're defined.
   * Recommended Order
   */
  STRICT_ORDER='STRICT_ORDER'
}

/**
 * Properties for defining a Stateful Rule Group
 */
interface StatefulRuleGroupProps {
  /**
   * The descriptive name of the stateful rule group
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
   * @default - undefined
   */
  readonly variables?: CfnRuleGroup.RuleVariablesProperty;

  /**
   * Rule Order
   * @default - STRICT_ORDER
   */
  readonly ruleOrder?: StatefulRuleOptions;

  /**
   * Description of the rule group
   * @default - undefined
   */
  readonly description?: string;
}

/**
 * Defines a Stateful Rule Group in the stack
 */
abstract class StatefulRuleGroup extends core.Resource implements IStatefulRuleGroup {

  /**
   * Reference existing Rule Group
   * @param scope
   * @param id
   * @param ruleGroupArn
   */
  public static fromRuleGroupArn(scope: Construct, id: string, ruleGroupArn: string): IStatefulRuleGroup {
    /**
     *
     */
    class Import extends StatelessRuleGroupBase {
      public readonly ruleGroupId = core.Fn.select(1, core.Fn.split('/', ruleGroupArn));
      public readonly ruleGroupArn = ruleGroupArn;
    }
    return new Import(scope, id);
  }

  public abstract readonly ruleGroupArn: string;
  public abstract readonly ruleGroupId: string;

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope:Construct, id:string, props?:StatefulRuleGroupProps) {
    if (props === undefined) {props = {};}
    super(scope, id, {
      physicalName: props.ruleGroupName,
    });

    /**
     * Validating Capacity
     */
    // default capacity to 200
    const capacity:number = props.capacity || 200;
    if (!Number.isInteger(capacity)) {
      throw new TypeError('capacity must be an integer value, '+
				`got: '${capacity}'`);
    }
    if (capacity < 0 || capacity > 30000) {
      throw new Error('capacity must be a positive value less than 30,000, '+
				`got: '${capacity}'`);
    }
  }
}

/**
 * Properties for defining a Stateful Suricata Rule Group
 * @resource AWS::NetworkFIrewall::RuleGroup
 */
export interface StatefulSuricataRuleGroupProps extends StatefulRuleGroupProps {
  /**
   * The suricata rules
   * @default - undefined
   */
  readonly rules?: string;
}

/**
 * Properties for defining a Stateful Suricata Rule Group from a file.
 * @resource AWS::NetworkFIrewall::RuleGroup
 */
export interface StatefulSuricataRuleGroupFromFileProps extends StatefulRuleGroupProps {
  /**
   * The suricata rules file location
   *
   */
  readonly path: string;

  /**
   * The encoding to use for the file
   * @default - uft-8
   */
  readonly encoding?: BufferEncoding;
}

/**
 * A Stateful Rule group that holds Suricata Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export class StatefulSuricataRuleGroup extends StatefulRuleGroup {

  /**
   * Reference Suricata rules from a file,
   * @param scope
   * @param id
   * @param props
   * @resource AWS::NetworkFirewall::RuleGroup
   */
  public static fromFile(scope:Construct, id:string, props:StatefulSuricataRuleGroupFromFileProps):StatefulSuricataRuleGroup {
    const contents = readFileSync(props.path, props.encoding || 'utf-8').toString();
    return new StatefulSuricataRuleGroup(scope, id, {
      rules: contents,
      ...props,
    });
  }

  public readonly ruleGroupArn: string;
  public readonly ruleGroupId: string;

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope:Construct, id:string, props?:StatefulSuricataRuleGroupProps) {
    if (props === undefined) {props = {};}
    super(scope, id, props);

    let rules:string = '';
    if (props.rules !== undefined) {
      rules = props.rules;
    }

    const resourceSourceProperty:CfnRuleGroup.RulesSourceProperty = {
      rulesString: rules,
    };

    const resourceRuleOptions:CfnRuleGroup.StatefulRuleOptionsProperty = {
      ruleOrder: props.ruleOrder || StatefulRuleOptions.STRICT_ORDER,
    };
    const resourceRuleGroupProperty:CfnRuleGroup.RuleGroupProperty = {
      rulesSource: resourceSourceProperty,
      ruleVariables: props.variables || {},
      statefulRuleOptions: resourceRuleOptions,
    };
    const resourceProps:CfnRuleGroupProps={
      capacity: props.capacity || 100,
      ruleGroupName: props.ruleGroupName || id,
      type: RuleGroupType.STATEFUL,
      ruleGroup: resourceRuleGroupProperty,
      description: props.description,
      //tags
    };

    const resource:CfnRuleGroup = new CfnRuleGroup(this, id, resourceProps);
    this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
    this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
      service: 'network-firewall',
      resource: 'stateful-rulegroup',
      resourceName: this.ruleGroupId,
    });
  }

}

/**
 * Properties for defining a Stateful 5 Tuple Rule Group
 * @resource AWS::NetworkFIrewall::RuleGroup
 */
export interface Stateful5TupleRuleGroupProps extends StatefulRuleGroupProps {
  /**
   * The rule group rules
   * @default - undefined
   */
  readonly rules?: Stateful5TupleRule[];
}

/**
 * A Stateful Rule group that holds 5Tuple Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
export class Stateful5TupleRuleGroup extends StatefulRuleGroup {

  public readonly ruleGroupArn: string;
  public readonly ruleGroupId: string;

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope:Construct, id:string, props?:Stateful5TupleRuleGroupProps) {
    if (props === undefined) {props = {};}
    super(scope, id, props);

    const rules:CfnRuleGroup.StatefulRuleProperty[] = [];
    if (props.rules !== undefined) {
      let rule: Stateful5TupleRule;
      for (rule of props.rules) {
        rules.push(rule.resource);
      }
    }

    const resourceSourceProperty:CfnRuleGroup.RulesSourceProperty={
      statefulRules: rules,
    };

    const resourceRuleOptions:CfnRuleGroup.StatefulRuleOptionsProperty = {
      ruleOrder: props.ruleOrder || StatefulRuleOptions.STRICT_ORDER,
    };

    const resourceRuleGroupProperty:CfnRuleGroup.RuleGroupProperty = {
      rulesSource: resourceSourceProperty,
      ruleVariables: props.variables || {},
      statefulRuleOptions: resourceRuleOptions,
    };

    const resourceProps:CfnRuleGroupProps={
      capacity: props.capacity || 100,
      ruleGroupName: props.ruleGroupName || id,
      type: RuleGroupType.STATEFUL,
      ruleGroup: resourceRuleGroupProperty,
      description: props.description,
      //tags
    };

    const resource:CfnRuleGroup = new CfnRuleGroup(this, id, resourceProps);

    this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
    this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
      service: 'network-firewall',
      resource: 'stateful-rulegroup',
      resourceName: this.ruleGroupId,
    });
  }
}

/**
 * Defines a Stateful Domain List Rule group in the stack
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
export class StatefulDomainListRuleGroup extends StatefulRuleGroup {

  public readonly ruleGroupArn: string;
  public readonly ruleGroupId: string;

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope:Construct, id:string, props?:StatefulDomainListRuleGroupProps) {
    if (props === undefined) {props = {};}
    super(scope, id, props);

    const resourceSourceProperty:CfnRuleGroup.RulesSourceProperty=(props.rule === undefined)?
      {}:{ rulesSourceList: props.rule.resource };

    const resourceRuleOptions:CfnRuleGroup.StatefulRuleOptionsProperty = {
      ruleOrder: props.ruleOrder || StatefulRuleOptions.STRICT_ORDER,
    };

    const resourceRuleGroupProperty:CfnRuleGroup.RuleGroupProperty = {
      rulesSource: resourceSourceProperty,
      ruleVariables: props.variables || {},
      statefulRuleOptions: resourceRuleOptions,
    };

    const resourceProps:CfnRuleGroupProps={
      capacity: props.capacity || 100,
      ruleGroupName: props.ruleGroupName || id,
      type: RuleGroupType.STATEFUL,
      ruleGroup: resourceRuleGroupProperty,
      description: props.description,
      //tags
    };

    const resource:CfnRuleGroup = new CfnRuleGroup(this, id, resourceProps);
    this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
    this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
      service: 'network-firewall',
      resource: 'stateful-rulegroup',
      resourceName: this.ruleGroupId,
    });
  }
}
