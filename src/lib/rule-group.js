"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StatefulDomainListRuleGroup = exports.Stateful5TupleRuleGroup = exports.StatefulSuricataRuleGroup = exports.StatefulRuleOptions = exports.StatelessRuleGroup = void 0;
const aws_networkfirewall_1 = require("aws-cdk-lib/aws-networkfirewall");
const core = require("aws-cdk-lib/core");
/**
 * The Possible Rule Group Types
 */
var RuleGroupType;
(function (RuleGroupType) {
    /**
       * For Stateless Rule Group Types
       */
    RuleGroupType["STATELESS"] = "STATELESS";
    /**
       * For Stateful Rule Group Types
       */
    RuleGroupType["STATEFUL"] = "STATEFUL";
})(RuleGroupType || (RuleGroupType = {}));
/**
 * The Base class for Stateless Rule Groups
 */
class StatelessRuleGroupBase extends core.Resource {
}
/**
 * A Stateless Rule group that holds Stateless Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
class StatelessRuleGroup extends StatelessRuleGroupBase {
    /**
     * Refernce existing Rule Group by Name
     */
    static fromStatelessRuleGroupName(scope, id, statelessRuleGroupName) {
        class Import extends StatelessRuleGroupBase {
            constructor() {
                super(...arguments);
                this.ruleGroupId = statelessRuleGroupName;
                this.ruleGroupArn = core.Stack.of(scope).formatArn({
                    service: 'network-firewall',
                    resource: 'stateful-rulegroup',
                    resourceName: statelessRuleGroupName,
                });
            }
        }
        return new Import(scope, id);
    }
    /**
     * Reference existing Rule Group by Arn
     */
    static fromStatelessRuleGroupArn(scope, id, statelessRuleGroupArn) {
        class Import extends StatelessRuleGroupBase {
            constructor() {
                super(...arguments);
                this.ruleGroupId = core.Fn.select(1, core.Fn.split('/', statelessRuleGroupArn));
                this.ruleGroupArn = statelessRuleGroupArn;
            }
        }
        return new Import(scope, id);
    }
    constructor(scope, id, props) {
        if (props === undefined) {
            props = {};
        }
        super(scope, id, {
            physicalName: props.ruleGroupName,
        });
        // Adding Validations
        /**
         * Validate ruleGroupId
         */
        if (props.ruleGroupName !== undefined &&
            !/^[a-zA-Z0-9-]+$/.test(props.ruleGroupName)) {
            throw new Error('ruleGroupName must be non-empty and contain only letters, numbers, and dashes, ' +
                `got: '${props.ruleGroupName}'`);
        }
        /**
         * Validate Rule priority
         */
        this.rules = props.rules || [];
        this.verifyPriorities();
        /**
         * Validating Capacity
         */
        const capacity = props.capacity || this.calculateCapacity();
        if (!Number.isInteger(capacity)) {
            throw new Error('Capacity must be an integer value, ' +
                `got: '${capacity}'`);
        }
        if (capacity < 0 || capacity > 30000) {
            throw new Error('Capacity must be a positive value less than 30,000, ' +
                `got: '${capacity}'`);
        }
        const statelessRules = [];
        if (props.rules !== undefined) {
            let rule;
            for (rule of props.rules) {
                statelessRules.push({
                    ruleDefinition: rule.rule.resource,
                    priority: rule.priority,
                });
            }
        }
        const statelessRulesAndCustomActions = {
            statelessRules: statelessRules,
            customActions: props.customActions,
        };
        const resourceRulesSource = {
            statelessRulesAndCustomActions: statelessRulesAndCustomActions,
        };
        //const resourceVariables:CfnRuleGroup.RuleVariablesProperty = props.variables;
        const resourceRuleGroupProperty = {
            rulesSource: resourceRulesSource,
            ruleVariables: props.variables,
        };
        const resourceProps = {
            capacity: capacity,
            ruleGroupName: props.ruleGroupName || id,
            type: RuleGroupType.STATELESS,
            ruleGroup: resourceRuleGroupProperty,
            description: props.description,
            //tags
        };
        const resource = new aws_networkfirewall_1.CfnRuleGroup(this, id, resourceProps);
        this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
        this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
            service: 'NetworkFirewall',
            resource: 'RuleGroup',
            resourceName: this.ruleGroupId,
        });
    }
    /**
     * Calculates the expected capacity required for all applied stateful rules.
     */
    calculateCapacity() {
        let total = 0;
        var statelessRule;
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
    verifyPriorities() {
        let priorities = [];
        let rule;
        for (rule of this.rules) {
            if (priorities.includes(rule.priority)) {
                throw new Error('Priority must be unique, ' +
                    `got duplicate priority: '${rule.priority}'`);
            }
            if (rule.priority < 0 || rule.priority > 30000) {
                throw new Error('Priority must be a positive value less than 30000' +
                    `got: '${rule.priority}'`);
            }
            priorities.push(rule.priority);
        }
    }
}
exports.StatelessRuleGroup = StatelessRuleGroup;
/**
 * Indicates how to manage the order of the rule evaluation for the rule group.
 */
var StatefulRuleOptions;
(function (StatefulRuleOptions) {
    /**
     * This is the default action
     * Stateful rules are provided to the rule engine as Suricata compatible strings, and Suricata evaluates them based on certain settings
     */
    StatefulRuleOptions["DEFAULT_ACTION_ORDER"] = "DEFAULT_ACTION_ORDER";
    /**
     * With strict ordering, the rule groups are evaluated by order of priority, starting from the lowest number, and the rules in each rule group are processed in the order in which they're defined.
     */
    StatefulRuleOptions["STRICT_ORDER"] = "STRICT_ORDER";
})(StatefulRuleOptions || (exports.StatefulRuleOptions = StatefulRuleOptions = {}));
/**
 * Defines a Stateful Rule Group in the stack
 */
class StatefulRuleGroup extends core.Resource {
    /**
     * Reference existing Rule Group
     */
    static fromRuleGroupArn(scope, id, ruleGroupArn) {
        class Import extends StatelessRuleGroupBase {
            constructor() {
                super(...arguments);
                this.ruleGroupId = core.Fn.select(1, core.Fn.split('/', ruleGroupArn));
                this.ruleGroupArn = ruleGroupArn;
            }
        }
        return new Import(scope, id);
    }
    constructor(scope, id, props) {
        if (props === undefined) {
            props = {};
        }
        super(scope, id, {
            physicalName: props.ruleGroupName,
        });
        /**
         * Validating Capacity
         */
        // default capacity to 200
        const capacity = props.capacity || 200;
        if (!Number.isInteger(capacity)) {
            throw new Error('capacity must be an integer value, ' +
                `got: '${capacity}'`);
        }
        if (capacity < 0 || capacity > 30000) {
            throw new Error('capacity must be a positive value less than 30,000, ' +
                `got: '${capacity}'`);
        }
    }
}
/**
 * A Stateful Rule group that holds Suricata Rules
 *
 * @resource AWS::NetworkFirewall::RuleGroup
 */
class StatefulSuricataRuleGroup extends StatefulRuleGroup {
    constructor(scope, id, props) {
        if (props === undefined) {
            props = {};
        }
        super(scope, id, props);
        let rules = '';
        if (props.rules !== undefined) {
            rules = props.rules;
        }
        const resourceSourceProperty = {
            rulesString: rules,
        };
        const resourceRuleOptions = {
            ruleOrder: props.ruleOrder || StatefulRuleOptions.DEFAULT_ACTION_ORDER,
        };
        const resourceRuleGroupProperty = {
            rulesSource: resourceSourceProperty,
            ruleVariables: props.variables || {},
            statefulRuleOptions: resourceRuleOptions,
        };
        const resourceProps = {
            capacity: props.capacity || 100,
            ruleGroupName: props.ruleGroupName || id,
            type: RuleGroupType.STATEFUL,
            ruleGroup: resourceRuleGroupProperty,
            description: props.description,
            //tags
        };
        const resource = new aws_networkfirewall_1.CfnRuleGroup(this, id, resourceProps);
        this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
        this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
            service: 'NetworkFirewall',
            resource: 'RuleGroup',
            resourceName: this.ruleGroupId,
        });
    }
}
exports.StatefulSuricataRuleGroup = StatefulSuricataRuleGroup;
/**
 * A Stateful Rule group that holds 5Tuple Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
class Stateful5TupleRuleGroup extends StatefulRuleGroup {
    constructor(scope, id, props) {
        if (props === undefined) {
            props = {};
        }
        super(scope, id, props);
        const rules = [];
        if (props.rules !== undefined) {
            let rule;
            for (rule of props.rules) {
                rules.push(rule.resource);
            }
        }
        const resourceSourceProperty = {
            statefulRules: rules,
        };
        const resourceRuleOptions = {
            ruleOrder: props.ruleOrder || StatefulRuleOptions.DEFAULT_ACTION_ORDER,
        };
        const resourceRuleGroupProperty = {
            rulesSource: resourceSourceProperty,
            ruleVariables: props.variables || {},
            statefulRuleOptions: resourceRuleOptions,
        };
        const resourceProps = {
            capacity: props.capacity || 100,
            ruleGroupName: props.ruleGroupName || id,
            type: RuleGroupType.STATEFUL,
            ruleGroup: resourceRuleGroupProperty,
            description: props.description,
            //tags
        };
        const resource = new aws_networkfirewall_1.CfnRuleGroup(this, id, resourceProps);
        this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
        this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
            service: 'NetworkFirewall',
            resource: 'RuleGroup',
            resourceName: this.ruleGroupId,
        });
    }
}
exports.Stateful5TupleRuleGroup = Stateful5TupleRuleGroup;
/**
 * A Stateful Rule group that holds Domain List Rules
 * @resource AWS::NetworkFirewall::RuleGroup
 */
class StatefulDomainListRuleGroup extends StatefulRuleGroup {
    constructor(scope, id, props) {
        if (props === undefined) {
            props = {};
        }
        super(scope, id, props);
        const resourceSourceProperty = (props.rule !== undefined) ?
            { rulesSourceList: props.rule.resource } : {};
        const resourceRuleOptions = {
            ruleOrder: props.ruleOrder || StatefulRuleOptions.DEFAULT_ACTION_ORDER,
        };
        const resourceRuleGroupProperty = {
            rulesSource: resourceSourceProperty,
            ruleVariables: props.variables || {},
            statefulRuleOptions: resourceRuleOptions,
        };
        const resourceProps = {
            capacity: props.capacity || 100,
            ruleGroupName: props.ruleGroupName || id,
            type: RuleGroupType.STATEFUL,
            ruleGroup: resourceRuleGroupProperty,
            description: props.description,
            //tags
        };
        const resource = new aws_networkfirewall_1.CfnRuleGroup(this, id, resourceProps);
        this.ruleGroupId = this.getResourceNameAttribute(resource.ref);
        this.ruleGroupArn = this.getResourceArnAttribute(resource.attrRuleGroupArn, {
            service: 'NetworkFirewall',
            resource: 'RuleGroup',
            resourceName: this.ruleGroupId,
        });
    }
}
exports.StatefulDomainListRuleGroup = StatefulDomainListRuleGroup;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicnVsZS1ncm91cC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInJ1bGUtZ3JvdXAudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQ0EseUVBQWtGO0FBRWxGLHlDQUF5QztBQW1CekM7O0dBRUc7QUFDSCxJQUFLLGFBVUo7QUFWRCxXQUFLLGFBQWE7SUFDaEI7O1NBRUU7SUFDRix3Q0FBdUIsQ0FBQTtJQUV2Qjs7U0FFRTtJQUNGLHNDQUFxQixDQUFBO0FBQ3ZCLENBQUMsRUFWSSxhQUFhLEtBQWIsYUFBYSxRQVVqQjtBQXFCRDs7R0FFRztBQUNILE1BQWUsc0JBQXVCLFNBQVEsSUFBSSxDQUFDLFFBQVE7Q0FHMUQ7QUFnREQ7OztHQUdHO0FBQ0gsTUFBYSxrQkFBbUIsU0FBUSxzQkFBc0I7SUFDNUQ7O09BRUc7SUFDSSxNQUFNLENBQUMsMEJBQTBCLENBQUMsS0FBZ0IsRUFBRSxFQUFVLEVBQUUsc0JBQThCO1FBQ25HLE1BQU0sTUFBTyxTQUFRLHNCQUFzQjtZQUEzQzs7Z0JBQ2tCLGdCQUFXLEdBQUcsc0JBQXNCLENBQUM7Z0JBQ3JDLGlCQUFZLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUMsU0FBUyxDQUFDO29CQUM1RCxPQUFPLEVBQUUsa0JBQWtCO29CQUMzQixRQUFRLEVBQUUsb0JBQW9CO29CQUM5QixZQUFZLEVBQUUsc0JBQXNCO2lCQUNyQyxDQUFDLENBQUM7WUFDTCxDQUFDO1NBQUE7UUFDRCxPQUFPLElBQUksTUFBTSxDQUFDLEtBQUssRUFBRSxFQUFFLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBRUQ7O09BRUc7SUFDSSxNQUFNLENBQUMseUJBQXlCLENBQUMsS0FBZ0IsRUFBRSxFQUFVLEVBQUUscUJBQTZCO1FBQ2pHLE1BQU0sTUFBTyxTQUFRLHNCQUFzQjtZQUEzQzs7Z0JBQ2tCLGdCQUFXLEdBQUcsSUFBSSxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLElBQUksQ0FBQyxFQUFFLENBQUMsS0FBSyxDQUFDLEdBQUcsRUFBRSxxQkFBcUIsQ0FBQyxDQUFDLENBQUM7Z0JBQzNFLGlCQUFZLEdBQUcscUJBQXFCLENBQUM7WUFDdkQsQ0FBQztTQUFBO1FBQ0QsT0FBTyxJQUFJLE1BQU0sQ0FBQyxLQUFLLEVBQUUsRUFBRSxDQUFDLENBQUM7SUFDL0IsQ0FBQztJQU1ELFlBQVksS0FBZ0IsRUFBRSxFQUFTLEVBQUUsS0FBK0I7UUFDdEUsSUFBSSxLQUFLLEtBQUssU0FBUyxFQUFFO1lBQUMsS0FBSyxHQUFHLEVBQUUsQ0FBQztTQUFDO1FBQ3RDLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFO1lBQ2YsWUFBWSxFQUFFLEtBQUssQ0FBQyxhQUFhO1NBQ2xDLENBQUMsQ0FBQztRQUVILHFCQUFxQjtRQUVyQjs7V0FFRztRQUNILElBQUksS0FBSyxDQUFDLGFBQWEsS0FBSyxTQUFTO1lBQ3JDLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUMsRUFBRTtZQUM1QyxNQUFNLElBQUksS0FBSyxDQUFDLGlGQUFpRjtnQkFDbkcsU0FBUyxLQUFLLENBQUMsYUFBYSxHQUFHLENBQUMsQ0FBQztTQUNoQztRQUVEOztXQUVHO1FBQ0gsSUFBSSxDQUFDLEtBQUssR0FBRyxLQUFLLENBQUMsS0FBSyxJQUFFLEVBQUUsQ0FBQztRQUM3QixJQUFJLENBQUMsZ0JBQWdCLEVBQUUsQ0FBQztRQUN4Qjs7V0FFRztRQUNILE1BQU0sUUFBUSxHQUFVLEtBQUssQ0FBQyxRQUFRLElBQUksSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7UUFDbkUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDLEVBQUU7WUFDL0IsTUFBTSxJQUFJLEtBQUssQ0FBQyxxQ0FBcUM7Z0JBQ3ZELFNBQVMsUUFBUSxHQUFHLENBQUMsQ0FBQztTQUNyQjtRQUNELElBQUksUUFBUSxHQUFHLENBQUMsSUFBSSxRQUFRLEdBQUcsS0FBSyxFQUFFO1lBQ3BDLE1BQU0sSUFBSSxLQUFLLENBQUMsc0RBQXNEO2dCQUN4RSxTQUFTLFFBQVEsR0FBRyxDQUFDLENBQUM7U0FDckI7UUFFRCxNQUFNLGNBQWMsR0FBd0MsRUFBRSxDQUFDO1FBQy9ELElBQUksS0FBSyxDQUFDLEtBQUssS0FBSyxTQUFTLEVBQUU7WUFDN0IsSUFBSSxJQUFzQixDQUFDO1lBQzNCLEtBQUssSUFBSSxJQUFJLEtBQUssQ0FBQyxLQUFLLEVBQUU7Z0JBQ3hCLGNBQWMsQ0FBQyxJQUFJLENBQ21CO29CQUNsQyxjQUFjLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRO29CQUNsQyxRQUFRLEVBQUUsSUFBSSxDQUFDLFFBQVE7aUJBQ3hCLENBQ0YsQ0FBQzthQUNIO1NBQ0Y7UUFFRCxNQUFNLDhCQUE4QixHQUFxRDtZQUN2RixjQUFjLEVBQUUsY0FBYztZQUM5QixhQUFhLEVBQUUsS0FBSyxDQUFDLGFBQWE7U0FDbkMsQ0FBQztRQUVGLE1BQU0sbUJBQW1CLEdBQW9DO1lBQzNELDhCQUE4QixFQUFFLDhCQUE4QjtTQUMvRCxDQUFDO1FBRUYsK0VBQStFO1FBRS9FLE1BQU0seUJBQXlCLEdBQWdDO1lBQzdELFdBQVcsRUFBRSxtQkFBbUI7WUFDaEMsYUFBYSxFQUFFLEtBQUssQ0FBQyxTQUFTO1NBQy9CLENBQUM7UUFFRixNQUFNLGFBQWEsR0FBbUI7WUFDcEMsUUFBUSxFQUFFLFFBQVE7WUFDbEIsYUFBYSxFQUFFLEtBQUssQ0FBQyxhQUFhLElBQUksRUFBRTtZQUN4QyxJQUFJLEVBQUUsYUFBYSxDQUFDLFNBQVM7WUFDN0IsU0FBUyxFQUFFLHlCQUF5QjtZQUNwQyxXQUFXLEVBQUUsS0FBSyxDQUFDLFdBQVc7WUFDOUIsTUFBTTtTQUNQLENBQUM7UUFDRixNQUFNLFFBQVEsR0FBZ0IsSUFBSSxrQ0FBWSxDQUFDLElBQUksRUFBRSxFQUFFLEVBQUUsYUFBYSxDQUFDLENBQUM7UUFDeEUsSUFBSSxDQUFDLFdBQVcsR0FBRyxJQUFJLENBQUMsd0JBQXdCLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQy9ELElBQUksQ0FBQyxZQUFZLEdBQUcsSUFBSSxDQUFDLHVCQUF1QixDQUFDLFFBQVEsQ0FBQyxnQkFBZ0IsRUFBRTtZQUMxRSxPQUFPLEVBQUUsaUJBQWlCO1lBQzFCLFFBQVEsRUFBRSxXQUFXO1lBQ3JCLFlBQVksRUFBRSxJQUFJLENBQUMsV0FBVztTQUMvQixDQUFDLENBQUM7SUFDTCxDQUFDO0lBRUQ7O09BRUc7SUFDSSxpQkFBaUI7UUFDdEIsSUFBSSxLQUFLLEdBQVUsQ0FBQyxDQUFDO1FBQ3JCLElBQUksYUFBZ0MsQ0FBQztRQUNyQyxJQUFJLElBQUksQ0FBQyxLQUFLLEtBQUssU0FBUyxFQUFFO1lBQzVCLEtBQUssYUFBYSxJQUFJLElBQUksQ0FBQyxLQUFLLEVBQUU7Z0JBQ2hDLEtBQUssSUFBSSxhQUFhLENBQUMsSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7YUFDakQ7U0FDRjtRQUNELE9BQU8sS0FBSyxDQUFDO0lBQ2YsQ0FBQztJQUVEOztPQUVHO0lBQ0ssZ0JBQWdCO1FBQ3RCLElBQUksVUFBVSxHQUFZLEVBQUUsQ0FBQztRQUM3QixJQUFJLElBQXNCLENBQUM7UUFDM0IsS0FBSyxJQUFJLElBQUksSUFBSSxDQUFDLEtBQUssRUFBRTtZQUN2QixJQUFJLFVBQVUsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxFQUFFO2dCQUN0QyxNQUFNLElBQUksS0FBSyxDQUFDLDJCQUEyQjtvQkFDekMsNEJBQTRCLElBQUksQ0FBQyxRQUFRLEdBQUcsQ0FBQyxDQUFDO2FBQ2pEO1lBQ0QsSUFBSSxJQUFJLENBQUMsUUFBUSxHQUFHLENBQUMsSUFBSSxJQUFJLENBQUMsUUFBUSxHQUFHLEtBQUssRUFBRTtnQkFDOUMsTUFBTSxJQUFJLEtBQUssQ0FBQyxtREFBbUQ7b0JBQ2pFLFNBQVMsSUFBSSxDQUFDLFFBQVEsR0FBRyxDQUFDLENBQUM7YUFDOUI7WUFDRCxVQUFVLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQztTQUNoQztJQUNILENBQUM7Q0FDRjtBQWhKRCxnREFnSkM7QUF5QkQ7O0dBRUc7QUFDSCxJQUFZLG1CQVdYO0FBWEQsV0FBWSxtQkFBbUI7SUFDN0I7OztPQUdHO0lBQ0gsb0VBQTJDLENBQUE7SUFFM0M7O09BRUc7SUFDSCxvREFBMkIsQ0FBQTtBQUM3QixDQUFDLEVBWFcsbUJBQW1CLG1DQUFuQixtQkFBbUIsUUFXOUI7QUEwQ0Q7O0dBRUc7QUFDSCxNQUFlLGlCQUFrQixTQUFRLElBQUksQ0FBQyxRQUFRO0lBRXBEOztPQUVHO0lBQ0ksTUFBTSxDQUFDLGdCQUFnQixDQUFDLEtBQWdCLEVBQUUsRUFBVSxFQUFFLFlBQW9CO1FBQy9FLE1BQU0sTUFBTyxTQUFRLHNCQUFzQjtZQUEzQzs7Z0JBQ2tCLGdCQUFXLEdBQUcsSUFBSSxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLElBQUksQ0FBQyxFQUFFLENBQUMsS0FBSyxDQUFDLEdBQUcsRUFBRSxZQUFZLENBQUMsQ0FBQyxDQUFDO2dCQUNsRSxpQkFBWSxHQUFHLFlBQVksQ0FBQztZQUM5QyxDQUFDO1NBQUE7UUFDRCxPQUFPLElBQUksTUFBTSxDQUFDLEtBQUssRUFBRSxFQUFFLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBS0QsWUFBWSxLQUFlLEVBQUUsRUFBUyxFQUFFLEtBQTZCO1FBQ25FLElBQUksS0FBSyxLQUFLLFNBQVMsRUFBRTtZQUFDLEtBQUssR0FBRyxFQUFFLENBQUM7U0FBQztRQUN0QyxLQUFLLENBQUMsS0FBSyxFQUFFLEVBQUUsRUFBRTtZQUNmLFlBQVksRUFBRSxLQUFLLENBQUMsYUFBYTtTQUNsQyxDQUFDLENBQUM7UUFFSDs7V0FFRztRQUNILDBCQUEwQjtRQUMxQixNQUFNLFFBQVEsR0FBVSxLQUFLLENBQUMsUUFBUSxJQUFJLEdBQUcsQ0FBQztRQUM5QyxJQUFJLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsRUFBRTtZQUMvQixNQUFNLElBQUksS0FBSyxDQUFDLHFDQUFxQztnQkFDdkQsU0FBUyxRQUFRLEdBQUcsQ0FBQyxDQUFDO1NBQ3JCO1FBQ0QsSUFBSSxRQUFRLEdBQUcsQ0FBQyxJQUFJLFFBQVEsR0FBRyxLQUFLLEVBQUU7WUFDcEMsTUFBTSxJQUFJLEtBQUssQ0FBQyxzREFBc0Q7Z0JBQ3hFLFNBQVMsUUFBUSxHQUFHLENBQUMsQ0FBQztTQUNyQjtJQUNILENBQUM7Q0FDRjtBQWdCRDs7OztHQUlHO0FBQ0gsTUFBYSx5QkFBMEIsU0FBUSxpQkFBaUI7SUFLOUQsWUFBWSxLQUFlLEVBQUUsRUFBUyxFQUFFLEtBQXFDO1FBQzNFLElBQUksS0FBSyxLQUFLLFNBQVMsRUFBRTtZQUFDLEtBQUssR0FBRyxFQUFFLENBQUM7U0FBQztRQUN0QyxLQUFLLENBQUMsS0FBSyxFQUFFLEVBQUUsRUFBRSxLQUFLLENBQUMsQ0FBQztRQUV4QixJQUFJLEtBQUssR0FBVSxFQUFFLENBQUM7UUFDdEIsSUFBSSxLQUFLLENBQUMsS0FBSyxLQUFLLFNBQVMsRUFBRTtZQUM3QixLQUFLLEdBQUcsS0FBSyxDQUFDLEtBQUssQ0FBQztTQUNyQjtRQUVELE1BQU0sc0JBQXNCLEdBQW9DO1lBQzlELFdBQVcsRUFBRSxLQUFLO1NBQ25CLENBQUM7UUFFRixNQUFNLG1CQUFtQixHQUE0QztZQUNuRSxTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVMsSUFBSSxtQkFBbUIsQ0FBQyxvQkFBb0I7U0FDdkUsQ0FBQztRQUNGLE1BQU0seUJBQXlCLEdBQWtDO1lBQy9ELFdBQVcsRUFBRSxzQkFBc0I7WUFDbkMsYUFBYSxFQUFFLEtBQUssQ0FBQyxTQUFTLElBQUksRUFBRTtZQUNwQyxtQkFBbUIsRUFBRSxtQkFBbUI7U0FDekMsQ0FBQztRQUNGLE1BQU0sYUFBYSxHQUFtQjtZQUNwQyxRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVEsSUFBSSxHQUFHO1lBQy9CLGFBQWEsRUFBRSxLQUFLLENBQUMsYUFBYSxJQUFJLEVBQUU7WUFDeEMsSUFBSSxFQUFFLGFBQWEsQ0FBQyxRQUFRO1lBQzVCLFNBQVMsRUFBRSx5QkFBeUI7WUFDcEMsV0FBVyxFQUFFLEtBQUssQ0FBQyxXQUFXO1lBQzlCLE1BQU07U0FDUCxDQUFDO1FBRUYsTUFBTSxRQUFRLEdBQWdCLElBQUksa0NBQVksQ0FBQyxJQUFJLEVBQUUsRUFBRSxFQUFFLGFBQWEsQ0FBQyxDQUFDO1FBQ3hFLElBQUksQ0FBQyxXQUFXLEdBQUcsSUFBSSxDQUFDLHdCQUF3QixDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUMvRCxJQUFJLENBQUMsWUFBWSxHQUFHLElBQUksQ0FBQyx1QkFBdUIsQ0FBQyxRQUFRLENBQUMsZ0JBQWdCLEVBQUU7WUFDMUUsT0FBTyxFQUFFLGlCQUFpQjtZQUMxQixRQUFRLEVBQUUsV0FBVztZQUNyQixZQUFZLEVBQUUsSUFBSSxDQUFDLFdBQVc7U0FDL0IsQ0FBQyxDQUFDO0lBQ0wsQ0FBQztDQUVGO0FBNUNELDhEQTRDQztBQWdCRDs7O0dBR0c7QUFDSCxNQUFhLHVCQUF3QixTQUFRLGlCQUFpQjtJQUs1RCxZQUFZLEtBQWUsRUFBRSxFQUFTLEVBQUUsS0FBbUM7UUFDekUsSUFBSSxLQUFLLEtBQUssU0FBUyxFQUFFO1lBQUMsS0FBSyxHQUFHLEVBQUUsQ0FBQztTQUFDO1FBQ3RDLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sS0FBSyxHQUF1QyxFQUFFLENBQUM7UUFDckQsSUFBSSxLQUFLLENBQUMsS0FBSyxLQUFLLFNBQVMsRUFBRTtZQUM3QixJQUFJLElBQXdCLENBQUM7WUFDN0IsS0FBSyxJQUFJLElBQUksS0FBSyxDQUFDLEtBQUssRUFBRTtnQkFDeEIsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUM7YUFDM0I7U0FDRjtRQUVELE1BQU0sc0JBQXNCLEdBQWtDO1lBQzVELGFBQWEsRUFBRSxLQUFLO1NBQ3JCLENBQUM7UUFFRixNQUFNLG1CQUFtQixHQUE0QztZQUNuRSxTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVMsSUFBSSxtQkFBbUIsQ0FBQyxvQkFBb0I7U0FDdkUsQ0FBQztRQUVGLE1BQU0seUJBQXlCLEdBQWtDO1lBQy9ELFdBQVcsRUFBRSxzQkFBc0I7WUFDbkMsYUFBYSxFQUFFLEtBQUssQ0FBQyxTQUFTLElBQUksRUFBRTtZQUNwQyxtQkFBbUIsRUFBRSxtQkFBbUI7U0FDekMsQ0FBQztRQUVGLE1BQU0sYUFBYSxHQUFtQjtZQUNwQyxRQUFRLEVBQUUsS0FBSyxDQUFDLFFBQVEsSUFBSSxHQUFHO1lBQy9CLGFBQWEsRUFBRSxLQUFLLENBQUMsYUFBYSxJQUFJLEVBQUU7WUFDeEMsSUFBSSxFQUFFLGFBQWEsQ0FBQyxRQUFRO1lBQzVCLFNBQVMsRUFBRSx5QkFBeUI7WUFDcEMsV0FBVyxFQUFFLEtBQUssQ0FBQyxXQUFXO1lBQzlCLE1BQU07U0FDUCxDQUFDO1FBRUYsTUFBTSxRQUFRLEdBQWdCLElBQUksa0NBQVksQ0FBQyxJQUFJLEVBQUUsRUFBRSxFQUFFLGFBQWEsQ0FBQyxDQUFDO1FBRXhFLElBQUksQ0FBQyxXQUFXLEdBQUcsSUFBSSxDQUFDLHdCQUF3QixDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUMvRCxJQUFJLENBQUMsWUFBWSxHQUFHLElBQUksQ0FBQyx1QkFBdUIsQ0FBQyxRQUFRLENBQUMsZ0JBQWdCLEVBQUU7WUFDMUUsT0FBTyxFQUFFLGlCQUFpQjtZQUMxQixRQUFRLEVBQUUsV0FBVztZQUNyQixZQUFZLEVBQUUsSUFBSSxDQUFDLFdBQVc7U0FDL0IsQ0FBQyxDQUFDO0lBQ0wsQ0FBQztDQUNGO0FBakRELDBEQWlEQztBQWVEOzs7R0FHRztBQUNILE1BQWEsMkJBQTRCLFNBQVEsaUJBQWlCO0lBS2hFLFlBQVksS0FBZSxFQUFFLEVBQVMsRUFBRSxLQUF1QztRQUM3RSxJQUFJLEtBQUssS0FBSyxTQUFTLEVBQUU7WUFBQyxLQUFLLEdBQUcsRUFBRSxDQUFDO1NBQUM7UUFDdEMsS0FBSyxDQUFDLEtBQUssRUFBRSxFQUFFLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFFeEIsTUFBTSxzQkFBc0IsR0FBa0MsQ0FBQyxLQUFLLENBQUMsSUFBSSxLQUFLLFNBQVMsQ0FBQyxDQUFBLENBQUM7WUFDdkYsRUFBRSxlQUFlLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQSxDQUFDLENBQUEsRUFBRSxDQUFDO1FBRTlDLE1BQU0sbUJBQW1CLEdBQTRDO1lBQ25FLFNBQVMsRUFBRSxLQUFLLENBQUMsU0FBUyxJQUFJLG1CQUFtQixDQUFDLG9CQUFvQjtTQUN2RSxDQUFDO1FBRUYsTUFBTSx5QkFBeUIsR0FBa0M7WUFDL0QsV0FBVyxFQUFFLHNCQUFzQjtZQUNuQyxhQUFhLEVBQUUsS0FBSyxDQUFDLFNBQVMsSUFBSSxFQUFFO1lBQ3BDLG1CQUFtQixFQUFFLG1CQUFtQjtTQUN6QyxDQUFDO1FBRUYsTUFBTSxhQUFhLEdBQW1CO1lBQ3BDLFFBQVEsRUFBRSxLQUFLLENBQUMsUUFBUSxJQUFJLEdBQUc7WUFDL0IsYUFBYSxFQUFFLEtBQUssQ0FBQyxhQUFhLElBQUksRUFBRTtZQUN4QyxJQUFJLEVBQUUsYUFBYSxDQUFDLFFBQVE7WUFDNUIsU0FBUyxFQUFFLHlCQUF5QjtZQUNwQyxXQUFXLEVBQUUsS0FBSyxDQUFDLFdBQVc7WUFDOUIsTUFBTTtTQUNQLENBQUM7UUFFRixNQUFNLFFBQVEsR0FBZ0IsSUFBSSxrQ0FBWSxDQUFDLElBQUksRUFBRSxFQUFFLEVBQUUsYUFBYSxDQUFDLENBQUM7UUFDeEUsSUFBSSxDQUFDLFdBQVcsR0FBRyxJQUFJLENBQUMsd0JBQXdCLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQy9ELElBQUksQ0FBQyxZQUFZLEdBQUcsSUFBSSxDQUFDLHVCQUF1QixDQUFDLFFBQVEsQ0FBQyxnQkFBZ0IsRUFBRTtZQUMxRSxPQUFPLEVBQUUsaUJBQWlCO1lBQzFCLFFBQVEsRUFBRSxXQUFXO1lBQ3JCLFlBQVksRUFBRSxJQUFJLENBQUMsV0FBVztTQUMvQixDQUFDLENBQUM7SUFDTCxDQUFDO0NBQ0Y7QUF2Q0Qsa0VBdUNDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQ29uc3RydWN0IH0gZnJvbSAnY29uc3RydWN0cyc7XG5pbXBvcnQgeyBDZm5SdWxlR3JvdXAsIENmblJ1bGVHcm91cFByb3BzIH0gZnJvbSAnYXdzLWNkay1saWIvYXdzLW5ldHdvcmtmaXJld2FsbCc7XG5pbXBvcnQgeyBTdGF0ZWxlc3NSdWxlLCBTdGF0ZWZ1bDVUdXBsZVJ1bGUsIFN0YXRlZnVsRG9tYWluTGlzdFJ1bGUgfSBmcm9tICcuL3J1bGUnO1xuaW1wb3J0ICogYXMgY29yZSBmcm9tICdhd3MtY2RrLWxpYi9jb3JlJztcblxuLy9pbXBvcnQgeyBTdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbiwgU3RhdGVmdWxTdGFuZGFyZEFjdGlvbiB9IGZyb20gJy4vYWN0aW9ucyc7XG5cbi8qKlxuICogTWFwcyBhIHByaW9yaXR5IHRvIGEgc3RhdGVsZXNzIHJ1bGVcbiAqL1xuZXhwb3J0IGludGVyZmFjZSBTdGF0ZWxlc3NSdWxlTGlzdHtcbiAgLyoqXG4gICAqIFRoZSBwcmlvcml0eSBvZiB0aGUgcnVsZSBpbiB0aGUgcnVsZSBncm91cFxuICAgKi9cbiAgcmVhZG9ubHkgcHJpb3JpdHk6IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIHN0YXRlbGVzcyBydWxlXG4gICAqL1xuICByZWFkb25seSBydWxlOiBTdGF0ZWxlc3NSdWxlO1xufVxuXG4vKipcbiAqIFRoZSBQb3NzaWJsZSBSdWxlIEdyb3VwIFR5cGVzXG4gKi9cbmVudW0gUnVsZUdyb3VwVHlwZSB7XG4gIC8qKlxuXHQgKiBGb3IgU3RhdGVsZXNzIFJ1bGUgR3JvdXAgVHlwZXNcblx0ICovXG4gIFNUQVRFTEVTUyA9ICdTVEFURUxFU1MnLFxuXG4gIC8qKlxuXHQgKiBGb3IgU3RhdGVmdWwgUnVsZSBHcm91cCBUeXBlc1xuXHQgKi9cbiAgU1RBVEVGVUwgPSAnU1RBVEVGVUwnLFxufVxuXG4vKipcbiAqIERlZmluZXMgYSBTdGF0ZWxlc3MgcnVsZSBHcm91cCBpbiB0aGUgc3RhY2tcbiAqL1xuZXhwb3J0IGludGVyZmFjZSBJU3RhdGVsZXNzUnVsZUdyb3VwIGV4dGVuZHMgY29yZS5JUmVzb3VyY2Uge1xuICAvKipcblx0ICogVGhlIEFybiBvZiB0aGUgcnVsZSBncm91cFxuXHQgKlxuXHQgKiBAYXR0cmlidXRlXG5cdCAqL1xuICByZWFkb25seSBydWxlR3JvdXBBcm46IHN0cmluZztcblxuICAvKipcblx0ICogdGhlIHBoeXNpY2FsIG5hbWUgb2YgdGhlIHJ1bGUgZ3JvdXBcblx0ICpcblx0ICogQGF0dHJpYnV0ZVxuXHQgKi9cbiAgcmVhZG9ubHkgcnVsZUdyb3VwSWQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBUaGUgQmFzZSBjbGFzcyBmb3IgU3RhdGVsZXNzIFJ1bGUgR3JvdXBzXG4gKi9cbmFic3RyYWN0IGNsYXNzIFN0YXRlbGVzc1J1bGVHcm91cEJhc2UgZXh0ZW5kcyBjb3JlLlJlc291cmNlIGltcGxlbWVudHMgSVN0YXRlbGVzc1J1bGVHcm91cCB7XG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBydWxlR3JvdXBBcm46IHN0cmluZztcbiAgcHVibGljIGFic3RyYWN0IHJlYWRvbmx5IHJ1bGVHcm91cElkOiBzdHJpbmc7XG59XG5cbi8qKlxuICogVGhlIHByb3BlcnRpZXMgZm9yIGRlZmluaW5nIGEgU3RhdGVsZXNzIFJ1bGUgR3JvdXBcbiAqL1xuZXhwb3J0IGludGVyZmFjZSBTdGF0ZWxlc3NSdWxlR3JvdXBQcm9wcyB7XG4gIC8qKlxuXHQgKiBUaGUgZGVzY3JpcHRpdmUgbmFtZSBvZiB0aGUgc3RhdGVsZXNzIHJ1bGUgZ3JvdXBcblx0ICpcblx0ICogQGRlZmF1bHQgLSBDbG91ZEZvcm1hdGlvbi1nZW5lcmF0ZWQgbmFtZVxuXHQgKi9cbiAgcmVhZG9ubHkgcnVsZUdyb3VwTmFtZT86IHN0cmluZztcbiAgLyoqXG5cdCAqIFRoZSBtYXhpbXVtIG9wZXJhdGluZyByZXNvdXJjZXMgdGhhdCB0aGlzIHJ1bGUgZ3JvdXAgY2FuIHVzZS5cblx0ICpcblx0ICogQGRlZmF1bHQgLSBDYXBhY2l0eSBpcyBDYWxjdWxhdGVkIGZyb20gcnVsZSByZXF1aXJlbWVudHMuXG5cdCAqL1xuICByZWFkb25seSBjYXBhY2l0eT86IG51bWJlcjtcblxuICAvKipcblx0ICogVGhlIHJ1bGUgZ3JvdXAgcnVsZXNcblx0ICpcblx0ICogQGRlZmF1bHQgPSB1bmRlZmluZWRcblx0ICovXG4gIHJlYWRvbmx5IHJ1bGVzPzogU3RhdGVsZXNzUnVsZUxpc3RbXTtcblxuICAvKipcblx0ICogQW4gb3B0aW9uYWwgTm9uLXN0YW5kYXJkIGFjdGlvbiB0byB1c2Vcblx0ICpcblx0ICogQGRlZmF1bHQgLSB1bmRlZmluZWRcblx0ICovXG4gIHJlYWRvbmx5IGN1c3RvbUFjdGlvbnM/OiBDZm5SdWxlR3JvdXAuQ3VzdG9tQWN0aW9uUHJvcGVydHlbXTtcblxuICAvKipcbiAgICogU2V0dGluZ3MgdGhhdCBhcmUgYXZhaWxhYmxlIGZvciB1c2UgaW4gdGhlIHJ1bGVzXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSB2YXJpYWJsZXM/OiBDZm5SdWxlR3JvdXAuUnVsZVZhcmlhYmxlc1Byb3BlcnR5O1xuXG4gIC8qKlxuICAgKiBEZXNjcmlwdGlvbiBvZiB0aGUgcnVsZSBncm91cFxuICAgKlxuICAgKiBAZGVmYXVsdCAtIHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogQSBTdGF0ZWxlc3MgUnVsZSBncm91cCB0aGF0IGhvbGRzIFN0YXRlbGVzcyBSdWxlc1xuICogQHJlc291cmNlIEFXUzo6TmV0d29ya0ZpcmV3YWxsOjpSdWxlR3JvdXBcbiAqL1xuZXhwb3J0IGNsYXNzIFN0YXRlbGVzc1J1bGVHcm91cCBleHRlbmRzIFN0YXRlbGVzc1J1bGVHcm91cEJhc2Uge1xuICAvKipcbiAgICogUmVmZXJuY2UgZXhpc3RpbmcgUnVsZSBHcm91cCBieSBOYW1lXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIGZyb21TdGF0ZWxlc3NSdWxlR3JvdXBOYW1lKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHN0YXRlbGVzc1J1bGVHcm91cE5hbWU6IHN0cmluZyk6IElTdGF0ZWxlc3NSdWxlR3JvdXAge1xuICAgIGNsYXNzIEltcG9ydCBleHRlbmRzIFN0YXRlbGVzc1J1bGVHcm91cEJhc2Uge1xuICAgICAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cElkID0gc3RhdGVsZXNzUnVsZUdyb3VwTmFtZTtcbiAgICAgIHB1YmxpYyByZWFkb25seSBydWxlR3JvdXBBcm4gPSBjb3JlLlN0YWNrLm9mKHNjb3BlKS5mb3JtYXRBcm4oe1xuICAgICAgICBzZXJ2aWNlOiAnbmV0d29yay1maXJld2FsbCcsXG4gICAgICAgIHJlc291cmNlOiAnc3RhdGVmdWwtcnVsZWdyb3VwJyxcbiAgICAgICAgcmVzb3VyY2VOYW1lOiBzdGF0ZWxlc3NSdWxlR3JvdXBOYW1lLFxuICAgICAgfSk7XG4gICAgfVxuICAgIHJldHVybiBuZXcgSW1wb3J0KHNjb3BlLCBpZCk7XG4gIH1cblxuICAvKipcbiAgICogUmVmZXJlbmNlIGV4aXN0aW5nIFJ1bGUgR3JvdXAgYnkgQXJuXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIGZyb21TdGF0ZWxlc3NSdWxlR3JvdXBBcm4oc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgc3RhdGVsZXNzUnVsZUdyb3VwQXJuOiBzdHJpbmcpOiBJU3RhdGVsZXNzUnVsZUdyb3VwIHtcbiAgICBjbGFzcyBJbXBvcnQgZXh0ZW5kcyBTdGF0ZWxlc3NSdWxlR3JvdXBCYXNlIHtcbiAgICAgIHB1YmxpYyByZWFkb25seSBydWxlR3JvdXBJZCA9IGNvcmUuRm4uc2VsZWN0KDEsIGNvcmUuRm4uc3BsaXQoJy8nLCBzdGF0ZWxlc3NSdWxlR3JvdXBBcm4pKTtcbiAgICAgIHB1YmxpYyByZWFkb25seSBydWxlR3JvdXBBcm4gPSBzdGF0ZWxlc3NSdWxlR3JvdXBBcm47XG4gICAgfVxuICAgIHJldHVybiBuZXcgSW1wb3J0KHNjb3BlLCBpZCk7XG4gIH1cblxuICBwdWJsaWMgcmVhZG9ubHkgcnVsZUdyb3VwSWQ6IHN0cmluZztcbiAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cEFybjogc3RyaW5nO1xuICBwcml2YXRlIHJ1bGVzOlN0YXRlbGVzc1J1bGVMaXN0W107XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6c3RyaW5nLCBwcm9wcz86IFN0YXRlbGVzc1J1bGVHcm91cFByb3BzKSB7XG4gICAgaWYgKHByb3BzID09PSB1bmRlZmluZWQpIHtwcm9wcyA9IHt9O31cbiAgICBzdXBlcihzY29wZSwgaWQsIHtcbiAgICAgIHBoeXNpY2FsTmFtZTogcHJvcHMucnVsZUdyb3VwTmFtZSxcbiAgICB9KTtcblxuICAgIC8vIEFkZGluZyBWYWxpZGF0aW9uc1xuXG4gICAgLyoqXG4gICAgICogVmFsaWRhdGUgcnVsZUdyb3VwSWRcbiAgICAgKi9cbiAgICBpZiAocHJvcHMucnVsZUdyb3VwTmFtZSAhPT0gdW5kZWZpbmVkICYmXG5cdFx0XHRcdCEvXlthLXpBLVowLTktXSskLy50ZXN0KHByb3BzLnJ1bGVHcm91cE5hbWUpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3J1bGVHcm91cE5hbWUgbXVzdCBiZSBub24tZW1wdHkgYW5kIGNvbnRhaW4gb25seSBsZXR0ZXJzLCBudW1iZXJzLCBhbmQgZGFzaGVzLCAnICtcblx0XHRcdFx0YGdvdDogJyR7cHJvcHMucnVsZUdyb3VwTmFtZX0nYCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmFsaWRhdGUgUnVsZSBwcmlvcml0eVxuICAgICAqL1xuICAgIHRoaXMucnVsZXMgPSBwcm9wcy5ydWxlc3x8W107XG4gICAgdGhpcy52ZXJpZnlQcmlvcml0aWVzKCk7XG4gICAgLyoqXG4gICAgICogVmFsaWRhdGluZyBDYXBhY2l0eVxuICAgICAqL1xuICAgIGNvbnN0IGNhcGFjaXR5Om51bWJlciA9IHByb3BzLmNhcGFjaXR5IHx8IHRoaXMuY2FsY3VsYXRlQ2FwYWNpdHkoKTtcbiAgICBpZiAoIU51bWJlci5pc0ludGVnZXIoY2FwYWNpdHkpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhcGFjaXR5IG11c3QgYmUgYW4gaW50ZWdlciB2YWx1ZSwgJytcblx0XHRcdFx0YGdvdDogJyR7Y2FwYWNpdHl9J2ApO1xuICAgIH1cbiAgICBpZiAoY2FwYWNpdHkgPCAwIHx8IGNhcGFjaXR5ID4gMzAwMDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQ2FwYWNpdHkgbXVzdCBiZSBhIHBvc2l0aXZlIHZhbHVlIGxlc3MgdGhhbiAzMCwwMDAsICcrXG5cdFx0XHRcdGBnb3Q6ICcke2NhcGFjaXR5fSdgKTtcbiAgICB9XG5cbiAgICBjb25zdCBzdGF0ZWxlc3NSdWxlczpDZm5SdWxlR3JvdXAuU3RhdGVsZXNzUnVsZVByb3BlcnR5W10gPSBbXTtcbiAgICBpZiAocHJvcHMucnVsZXMgIT09IHVuZGVmaW5lZCkge1xuICAgICAgbGV0IHJ1bGU6U3RhdGVsZXNzUnVsZUxpc3Q7XG4gICAgICBmb3IgKHJ1bGUgb2YgcHJvcHMucnVsZXMpIHtcbiAgICAgICAgc3RhdGVsZXNzUnVsZXMucHVzaChcbiAgICAgICAgICA8Q2ZuUnVsZUdyb3VwLlN0YXRlbGVzc1J1bGVQcm9wZXJ0eT57XG4gICAgICAgICAgICBydWxlRGVmaW5pdGlvbjogcnVsZS5ydWxlLnJlc291cmNlLFxuICAgICAgICAgICAgcHJpb3JpdHk6IHJ1bGUucHJpb3JpdHksXG4gICAgICAgICAgfSxcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBzdGF0ZWxlc3NSdWxlc0FuZEN1c3RvbUFjdGlvbnM6Q2ZuUnVsZUdyb3VwLlN0YXRlbGVzc1J1bGVzQW5kQ3VzdG9tQWN0aW9uc1Byb3BlcnR5PXtcbiAgICAgIHN0YXRlbGVzc1J1bGVzOiBzdGF0ZWxlc3NSdWxlcyxcbiAgICAgIGN1c3RvbUFjdGlvbnM6IHByb3BzLmN1c3RvbUFjdGlvbnMsXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlUnVsZXNTb3VyY2U6Q2ZuUnVsZUdyb3VwLlJ1bGVzU291cmNlUHJvcGVydHkgPSB7XG4gICAgICBzdGF0ZWxlc3NSdWxlc0FuZEN1c3RvbUFjdGlvbnM6IHN0YXRlbGVzc1J1bGVzQW5kQ3VzdG9tQWN0aW9ucyxcbiAgICB9O1xuXG4gICAgLy9jb25zdCByZXNvdXJjZVZhcmlhYmxlczpDZm5SdWxlR3JvdXAuUnVsZVZhcmlhYmxlc1Byb3BlcnR5ID0gcHJvcHMudmFyaWFibGVzO1xuXG4gICAgY29uc3QgcmVzb3VyY2VSdWxlR3JvdXBQcm9wZXJ0eTpDZm5SdWxlR3JvdXAuUnVsZUdyb3VwUHJvcGVydHk9e1xuICAgICAgcnVsZXNTb3VyY2U6IHJlc291cmNlUnVsZXNTb3VyY2UsXG4gICAgICBydWxlVmFyaWFibGVzOiBwcm9wcy52YXJpYWJsZXMsXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlUHJvcHM6Q2ZuUnVsZUdyb3VwUHJvcHM9e1xuICAgICAgY2FwYWNpdHk6IGNhcGFjaXR5LFxuICAgICAgcnVsZUdyb3VwTmFtZTogcHJvcHMucnVsZUdyb3VwTmFtZSB8fCBpZCxcbiAgICAgIHR5cGU6IFJ1bGVHcm91cFR5cGUuU1RBVEVMRVNTLFxuICAgICAgcnVsZUdyb3VwOiByZXNvdXJjZVJ1bGVHcm91cFByb3BlcnR5LFxuICAgICAgZGVzY3JpcHRpb246IHByb3BzLmRlc2NyaXB0aW9uLFxuICAgICAgLy90YWdzXG4gICAgfTtcbiAgICBjb25zdCByZXNvdXJjZTpDZm5SdWxlR3JvdXAgPSBuZXcgQ2ZuUnVsZUdyb3VwKHRoaXMsIGlkLCByZXNvdXJjZVByb3BzKTtcbiAgICB0aGlzLnJ1bGVHcm91cElkID0gdGhpcy5nZXRSZXNvdXJjZU5hbWVBdHRyaWJ1dGUocmVzb3VyY2UucmVmKTtcbiAgICB0aGlzLnJ1bGVHcm91cEFybiA9IHRoaXMuZ2V0UmVzb3VyY2VBcm5BdHRyaWJ1dGUocmVzb3VyY2UuYXR0clJ1bGVHcm91cEFybiwge1xuICAgICAgc2VydmljZTogJ05ldHdvcmtGaXJld2FsbCcsXG4gICAgICByZXNvdXJjZTogJ1J1bGVHcm91cCcsXG4gICAgICByZXNvdXJjZU5hbWU6IHRoaXMucnVsZUdyb3VwSWQsXG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQ2FsY3VsYXRlcyB0aGUgZXhwZWN0ZWQgY2FwYWNpdHkgcmVxdWlyZWQgZm9yIGFsbCBhcHBsaWVkIHN0YXRlZnVsIHJ1bGVzLlxuICAgKi9cbiAgcHVibGljIGNhbGN1bGF0ZUNhcGFjaXR5KCk6IG51bWJlciB7XG4gICAgbGV0IHRvdGFsOm51bWJlciA9IDA7XG4gICAgdmFyIHN0YXRlbGVzc1J1bGU6IFN0YXRlbGVzc1J1bGVMaXN0O1xuICAgIGlmICh0aGlzLnJ1bGVzICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIGZvciAoc3RhdGVsZXNzUnVsZSBvZiB0aGlzLnJ1bGVzKSB7XG4gICAgICAgIHRvdGFsICs9IHN0YXRlbGVzc1J1bGUucnVsZS5jYWxjdWxhdGVDYXBhY2l0eSgpO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdG90YWw7XG4gIH1cblxuICAvKipcbiAgICogRW5zdXJlIGFsbCBwcmlvcml0aWVzIGFyZSB3aXRoaW4gYWxsb3dlZCByYW5nZSB2YWx1ZXNcbiAgICovXG4gIHByaXZhdGUgdmVyaWZ5UHJpb3JpdGllcygpIHtcbiAgICBsZXQgcHJpb3JpdGllczpudW1iZXJbXSA9IFtdO1xuICAgIGxldCBydWxlOlN0YXRlbGVzc1J1bGVMaXN0O1xuICAgIGZvciAocnVsZSBvZiB0aGlzLnJ1bGVzKSB7XG4gICAgICBpZiAocHJpb3JpdGllcy5pbmNsdWRlcyhydWxlLnByaW9yaXR5KSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1ByaW9yaXR5IG11c3QgYmUgdW5pcXVlLCAnK1xuICAgICAgICAgIGBnb3QgZHVwbGljYXRlIHByaW9yaXR5OiAnJHtydWxlLnByaW9yaXR5fSdgKTtcbiAgICAgIH1cbiAgICAgIGlmIChydWxlLnByaW9yaXR5IDwgMCB8fCBydWxlLnByaW9yaXR5ID4gMzAwMDApIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdQcmlvcml0eSBtdXN0IGJlIGEgcG9zaXRpdmUgdmFsdWUgbGVzcyB0aGFuIDMwMDAwJytcbiAgICAgICAgICBgZ290OiAnJHtydWxlLnByaW9yaXR5fSdgKTtcbiAgICAgIH1cbiAgICAgIHByaW9yaXRpZXMucHVzaChydWxlLnByaW9yaXR5KTtcbiAgICB9XG4gIH1cbn1cblxuLy9cbi8vICBEZWZpbmUgU3RhdGVmdWwgUnVsZSBHcm91cHNcbi8vXG5cbi8qKlxuICogVGhlIEludGVyZmFjZSB0aGF0IHJlcHJlc2VudHMgYSBTdGF0ZWZ1bCBSdWxlIEdyb3VwXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSVN0YXRlZnVsUnVsZUdyb3VwIGV4dGVuZHMgY29yZS5JUmVzb3VyY2Uge1xuICAvKipcbiAgICogVGhlIEFybiBvZiB0aGUgcnVsZSBncm91cFxuICAgKlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICByZWFkb25seSBydWxlR3JvdXBBcm46IHN0cmluZztcblxuICAvKipcbiAgICogdGhlIHBoeXNpY2FsIG5hbWUgb2YgdGhlIHJ1bGUgZ3JvdXBcbiAgICpcbiAgICogQGF0dHJpYnV0ZVxuICAgKi9cbiAgcmVhZG9ubHkgcnVsZUdyb3VwSWQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBJbmRpY2F0ZXMgaG93IHRvIG1hbmFnZSB0aGUgb3JkZXIgb2YgdGhlIHJ1bGUgZXZhbHVhdGlvbiBmb3IgdGhlIHJ1bGUgZ3JvdXAuXG4gKi9cbmV4cG9ydCBlbnVtIFN0YXRlZnVsUnVsZU9wdGlvbnMge1xuICAvKipcbiAgICogVGhpcyBpcyB0aGUgZGVmYXVsdCBhY3Rpb25cbiAgICogU3RhdGVmdWwgcnVsZXMgYXJlIHByb3ZpZGVkIHRvIHRoZSBydWxlIGVuZ2luZSBhcyBTdXJpY2F0YSBjb21wYXRpYmxlIHN0cmluZ3MsIGFuZCBTdXJpY2F0YSBldmFsdWF0ZXMgdGhlbSBiYXNlZCBvbiBjZXJ0YWluIHNldHRpbmdzXG4gICAqL1xuICBERUZBVUxUX0FDVElPTl9PUkRFUj0nREVGQVVMVF9BQ1RJT05fT1JERVInLFxuXG4gIC8qKlxuICAgKiBXaXRoIHN0cmljdCBvcmRlcmluZywgdGhlIHJ1bGUgZ3JvdXBzIGFyZSBldmFsdWF0ZWQgYnkgb3JkZXIgb2YgcHJpb3JpdHksIHN0YXJ0aW5nIGZyb20gdGhlIGxvd2VzdCBudW1iZXIsIGFuZCB0aGUgcnVsZXMgaW4gZWFjaCBydWxlIGdyb3VwIGFyZSBwcm9jZXNzZWQgaW4gdGhlIG9yZGVyIGluIHdoaWNoIHRoZXkncmUgZGVmaW5lZC5cbiAgICovXG4gIFNUUklDVF9PUkRFUj0nU1RSSUNUX09SREVSJ1xufVxuXG4vKipcbiAqIFByb3BlcnRpZXMgZm9yIGRlZmluaW5nIGEgU3RhdGVmdWwgUnVsZSBHcm91cFxuICovXG5pbnRlcmZhY2UgU3RhdGVmdWxSdWxlR3JvdXBQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgZGVzY3JpcHRpdmUgbmFtZSBvZiB0aGUgc3RhdGVmdWwgcnVsZSBncm91cFxuICAgKlxuICAgKiBAZGVmYXVsdCAtIENsb3VkRm9ybWF0aW9uLWdlbmVyYXRlZCBuYW1lXG4gICAqL1xuICByZWFkb25seSBydWxlR3JvdXBOYW1lPzogc3RyaW5nO1xuICAvKipcbiAgICogVGhlIG1heGltdW0gb3BlcmF0aW5nIHJlc291cmNlcyB0aGF0IHRoaXMgcnVsZSBncm91cCBjYW4gdXNlLlxuICAgKiBFc3RpbWF0ZSBhIHN0YXRlZnVsIHJ1bGUgZ3JvdXAncyBjYXBhY2l0eSBhcyB0aGUgbnVtYmVyIG9mIHJ1bGVzIHRoYXQgeW91IGV4cGVjdCB0byBoYXZlIGluIGl0IGR1cmluZyBpdHMgbGlmZXRpbWUuXG4gICAqIFlvdSBjYW4ndCBjaGFuZ2UgdGhpcyBzZXR0aW5nIGFmdGVyIHlvdSBjcmVhdGUgdGhlIHJ1bGUgZ3JvdXBcbiAgICogQGRlZmF1bHQgLSAyMDBcbiAgICovXG4gIHJlYWRvbmx5IGNhcGFjaXR5PzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBTZXR0aW5ncyB0aGF0IGFyZSBhdmFpbGFibGUgZm9yIHVzZSBpbiB0aGUgcnVsZXNcbiAgICpcbiAgICogQGRlZmF1bHQgLSB1bmRlZmluZWRcbiAgICovXG4gIHJlYWRvbmx5IHZhcmlhYmxlcz86IENmblJ1bGVHcm91cC5SdWxlVmFyaWFibGVzUHJvcGVydHk7XG5cbiAgLyoqXG4gICAqIFJ1bGUgT3JkZXJcbiAgICpcbiAgICogQGRlZmF1bHQgLSBERUZBVUxUX1JVTEVfQUNUSU9OX09SREVSXG4gICAqL1xuICByZWFkb25seSBydWxlT3JkZXI/OiBTdGF0ZWZ1bFJ1bGVPcHRpb25zO1xuXG4gIC8qKlxuICAgKiBEZXNjcmlwdGlvbiBvZiB0aGUgcnVsZSBncm91cFxuICAgKlxuICAgKiBAZGVmYXVsdCAtIHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogRGVmaW5lcyBhIFN0YXRlZnVsIFJ1bGUgR3JvdXAgaW4gdGhlIHN0YWNrXG4gKi9cbmFic3RyYWN0IGNsYXNzIFN0YXRlZnVsUnVsZUdyb3VwIGV4dGVuZHMgY29yZS5SZXNvdXJjZSBpbXBsZW1lbnRzIElTdGF0ZWZ1bFJ1bGVHcm91cCB7XG5cbiAgLyoqXG4gICAqIFJlZmVyZW5jZSBleGlzdGluZyBSdWxlIEdyb3VwXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIGZyb21SdWxlR3JvdXBBcm4oc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcnVsZUdyb3VwQXJuOiBzdHJpbmcpOiBJU3RhdGVmdWxSdWxlR3JvdXAge1xuICAgIGNsYXNzIEltcG9ydCBleHRlbmRzIFN0YXRlbGVzc1J1bGVHcm91cEJhc2Uge1xuICAgICAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cElkID0gY29yZS5Gbi5zZWxlY3QoMSwgY29yZS5Gbi5zcGxpdCgnLycsIHJ1bGVHcm91cEFybikpO1xuICAgICAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cEFybiA9IHJ1bGVHcm91cEFybjtcbiAgICB9XG4gICAgcmV0dXJuIG5ldyBJbXBvcnQoc2NvcGUsIGlkKTtcbiAgfVxuXG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBydWxlR3JvdXBBcm46IHN0cmluZztcbiAgcHVibGljIGFic3RyYWN0IHJlYWRvbmx5IHJ1bGVHcm91cElkOiBzdHJpbmc7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6Q29uc3RydWN0LCBpZDpzdHJpbmcsIHByb3BzPzpTdGF0ZWZ1bFJ1bGVHcm91cFByb3BzKSB7XG4gICAgaWYgKHByb3BzID09PSB1bmRlZmluZWQpIHtwcm9wcyA9IHt9O31cbiAgICBzdXBlcihzY29wZSwgaWQsIHtcbiAgICAgIHBoeXNpY2FsTmFtZTogcHJvcHMucnVsZUdyb3VwTmFtZSxcbiAgICB9KTtcblxuICAgIC8qKlxuICAgICAqIFZhbGlkYXRpbmcgQ2FwYWNpdHlcbiAgICAgKi9cbiAgICAvLyBkZWZhdWx0IGNhcGFjaXR5IHRvIDIwMFxuICAgIGNvbnN0IGNhcGFjaXR5Om51bWJlciA9IHByb3BzLmNhcGFjaXR5IHx8IDIwMDtcbiAgICBpZiAoIU51bWJlci5pc0ludGVnZXIoY2FwYWNpdHkpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ2NhcGFjaXR5IG11c3QgYmUgYW4gaW50ZWdlciB2YWx1ZSwgJytcblx0XHRcdFx0YGdvdDogJyR7Y2FwYWNpdHl9J2ApO1xuICAgIH1cbiAgICBpZiAoY2FwYWNpdHkgPCAwIHx8IGNhcGFjaXR5ID4gMzAwMDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignY2FwYWNpdHkgbXVzdCBiZSBhIHBvc2l0aXZlIHZhbHVlIGxlc3MgdGhhbiAzMCwwMDAsICcrXG5cdFx0XHRcdGBnb3Q6ICcke2NhcGFjaXR5fSdgKTtcbiAgICB9XG4gIH1cbn1cblxuLyoqXG4gKiBQcm9wZXJ0aWVzIGZvciBkZWZpbmluZyBhIFN0YXRlZnVsIFN1cmljYXRhIFJ1bGUgR3JvdXBcbiAqXG4gKiBAcmVzb3VyY2UgQVdTOjpOZXR3b3JrRklyZXdhbGw6OlJ1bGVHcm91cFxuICovXG5leHBvcnQgaW50ZXJmYWNlIFN0YXRlZnVsU3VyaWNhdGFSdWxlR3JvdXBQcm9wcyBleHRlbmRzIFN0YXRlZnVsUnVsZUdyb3VwUHJvcHMge1xuICAvKipcbiAgICogVGhlIHN1cmljYXRhIHJ1bGVzXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSBydWxlcz86IHN0cmluZztcbn1cblxuLyoqXG4gKiBBIFN0YXRlZnVsIFJ1bGUgZ3JvdXAgdGhhdCBob2xkcyBTdXJpY2F0YSBSdWxlc1xuICpcbiAqIEByZXNvdXJjZSBBV1M6Ok5ldHdvcmtGaXJld2FsbDo6UnVsZUdyb3VwXG4gKi9cbmV4cG9ydCBjbGFzcyBTdGF0ZWZ1bFN1cmljYXRhUnVsZUdyb3VwIGV4dGVuZHMgU3RhdGVmdWxSdWxlR3JvdXAge1xuXG4gIHB1YmxpYyByZWFkb25seSBydWxlR3JvdXBBcm46IHN0cmluZztcbiAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cElkOiBzdHJpbmc7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6Q29uc3RydWN0LCBpZDpzdHJpbmcsIHByb3BzPzpTdGF0ZWZ1bFN1cmljYXRhUnVsZUdyb3VwUHJvcHMpIHtcbiAgICBpZiAocHJvcHMgPT09IHVuZGVmaW5lZCkge3Byb3BzID0ge307fVxuICAgIHN1cGVyKHNjb3BlLCBpZCwgcHJvcHMpO1xuXG4gICAgbGV0IHJ1bGVzOnN0cmluZyA9ICcnO1xuICAgIGlmIChwcm9wcy5ydWxlcyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBydWxlcyA9IHByb3BzLnJ1bGVzO1xuICAgIH1cblxuICAgIGNvbnN0IHJlc291cmNlU291cmNlUHJvcGVydHk6Q2ZuUnVsZUdyb3VwLlJ1bGVzU291cmNlUHJvcGVydHkgPSB7XG4gICAgICBydWxlc1N0cmluZzogcnVsZXMsXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlUnVsZU9wdGlvbnM6Q2ZuUnVsZUdyb3VwLlN0YXRlZnVsUnVsZU9wdGlvbnNQcm9wZXJ0eSA9IHtcbiAgICAgIHJ1bGVPcmRlcjogcHJvcHMucnVsZU9yZGVyIHx8IFN0YXRlZnVsUnVsZU9wdGlvbnMuREVGQVVMVF9BQ1RJT05fT1JERVIsXG4gICAgfTtcbiAgICBjb25zdCByZXNvdXJjZVJ1bGVHcm91cFByb3BlcnR5OkNmblJ1bGVHcm91cC5SdWxlR3JvdXBQcm9wZXJ0eSA9IHtcbiAgICAgIHJ1bGVzU291cmNlOiByZXNvdXJjZVNvdXJjZVByb3BlcnR5LFxuICAgICAgcnVsZVZhcmlhYmxlczogcHJvcHMudmFyaWFibGVzIHx8IHt9LFxuICAgICAgc3RhdGVmdWxSdWxlT3B0aW9uczogcmVzb3VyY2VSdWxlT3B0aW9ucyxcbiAgICB9O1xuICAgIGNvbnN0IHJlc291cmNlUHJvcHM6Q2ZuUnVsZUdyb3VwUHJvcHM9e1xuICAgICAgY2FwYWNpdHk6IHByb3BzLmNhcGFjaXR5IHx8IDEwMCxcbiAgICAgIHJ1bGVHcm91cE5hbWU6IHByb3BzLnJ1bGVHcm91cE5hbWUgfHwgaWQsXG4gICAgICB0eXBlOiBSdWxlR3JvdXBUeXBlLlNUQVRFRlVMLFxuICAgICAgcnVsZUdyb3VwOiByZXNvdXJjZVJ1bGVHcm91cFByb3BlcnR5LFxuICAgICAgZGVzY3JpcHRpb246IHByb3BzLmRlc2NyaXB0aW9uLFxuICAgICAgLy90YWdzXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlOkNmblJ1bGVHcm91cCA9IG5ldyBDZm5SdWxlR3JvdXAodGhpcywgaWQsIHJlc291cmNlUHJvcHMpO1xuICAgIHRoaXMucnVsZUdyb3VwSWQgPSB0aGlzLmdldFJlc291cmNlTmFtZUF0dHJpYnV0ZShyZXNvdXJjZS5yZWYpO1xuICAgIHRoaXMucnVsZUdyb3VwQXJuID0gdGhpcy5nZXRSZXNvdXJjZUFybkF0dHJpYnV0ZShyZXNvdXJjZS5hdHRyUnVsZUdyb3VwQXJuLCB7XG4gICAgICBzZXJ2aWNlOiAnTmV0d29ya0ZpcmV3YWxsJyxcbiAgICAgIHJlc291cmNlOiAnUnVsZUdyb3VwJyxcbiAgICAgIHJlc291cmNlTmFtZTogdGhpcy5ydWxlR3JvdXBJZCxcbiAgICB9KTtcbiAgfVxuXG59XG5cbi8qKlxuICogUHJvcGVydGllcyBmb3IgZGVmaW5pbmcgYSBTdGF0ZWZ1bCA1IFR1cGxlIFJ1bGUgR3JvdXBcbiAqXG4gKiBAcmVzb3VyY2UgQVdTOjpOZXR3b3JrRklyZXdhbGw6OlJ1bGVHcm91cFxuICovXG5leHBvcnQgaW50ZXJmYWNlIFN0YXRlZnVsNVR1cGxlUnVsZUdyb3VwUHJvcHMgZXh0ZW5kcyBTdGF0ZWZ1bFJ1bGVHcm91cFByb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBydWxlIGdyb3VwIHJ1bGVzXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSBydWxlcz86IFN0YXRlZnVsNVR1cGxlUnVsZVtdO1xufVxuXG4vKipcbiAqIEEgU3RhdGVmdWwgUnVsZSBncm91cCB0aGF0IGhvbGRzIDVUdXBsZSBSdWxlc1xuICogQHJlc291cmNlIEFXUzo6TmV0d29ya0ZpcmV3YWxsOjpSdWxlR3JvdXBcbiAqL1xuZXhwb3J0IGNsYXNzIFN0YXRlZnVsNVR1cGxlUnVsZUdyb3VwIGV4dGVuZHMgU3RhdGVmdWxSdWxlR3JvdXAge1xuXG4gIHB1YmxpYyByZWFkb25seSBydWxlR3JvdXBBcm46IHN0cmluZztcbiAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cElkOiBzdHJpbmc7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6Q29uc3RydWN0LCBpZDpzdHJpbmcsIHByb3BzPzpTdGF0ZWZ1bDVUdXBsZVJ1bGVHcm91cFByb3BzKSB7XG4gICAgaWYgKHByb3BzID09PSB1bmRlZmluZWQpIHtwcm9wcyA9IHt9O31cbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIGNvbnN0IHJ1bGVzOkNmblJ1bGVHcm91cC5TdGF0ZWZ1bFJ1bGVQcm9wZXJ0eVtdID0gW107XG4gICAgaWYgKHByb3BzLnJ1bGVzICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIGxldCBydWxlOiBTdGF0ZWZ1bDVUdXBsZVJ1bGU7XG4gICAgICBmb3IgKHJ1bGUgb2YgcHJvcHMucnVsZXMpIHtcbiAgICAgICAgcnVsZXMucHVzaChydWxlLnJlc291cmNlKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCByZXNvdXJjZVNvdXJjZVByb3BlcnR5OkNmblJ1bGVHcm91cC5SdWxlc1NvdXJjZVByb3BlcnR5PXtcbiAgICAgIHN0YXRlZnVsUnVsZXM6IHJ1bGVzLFxuICAgIH07XG5cbiAgICBjb25zdCByZXNvdXJjZVJ1bGVPcHRpb25zOkNmblJ1bGVHcm91cC5TdGF0ZWZ1bFJ1bGVPcHRpb25zUHJvcGVydHkgPSB7XG4gICAgICBydWxlT3JkZXI6IHByb3BzLnJ1bGVPcmRlciB8fCBTdGF0ZWZ1bFJ1bGVPcHRpb25zLkRFRkFVTFRfQUNUSU9OX09SREVSLFxuICAgIH07XG5cbiAgICBjb25zdCByZXNvdXJjZVJ1bGVHcm91cFByb3BlcnR5OkNmblJ1bGVHcm91cC5SdWxlR3JvdXBQcm9wZXJ0eSA9IHtcbiAgICAgIHJ1bGVzU291cmNlOiByZXNvdXJjZVNvdXJjZVByb3BlcnR5LFxuICAgICAgcnVsZVZhcmlhYmxlczogcHJvcHMudmFyaWFibGVzIHx8IHt9LFxuICAgICAgc3RhdGVmdWxSdWxlT3B0aW9uczogcmVzb3VyY2VSdWxlT3B0aW9ucyxcbiAgICB9O1xuXG4gICAgY29uc3QgcmVzb3VyY2VQcm9wczpDZm5SdWxlR3JvdXBQcm9wcz17XG4gICAgICBjYXBhY2l0eTogcHJvcHMuY2FwYWNpdHkgfHwgMTAwLFxuICAgICAgcnVsZUdyb3VwTmFtZTogcHJvcHMucnVsZUdyb3VwTmFtZSB8fCBpZCxcbiAgICAgIHR5cGU6IFJ1bGVHcm91cFR5cGUuU1RBVEVGVUwsXG4gICAgICBydWxlR3JvdXA6IHJlc291cmNlUnVsZUdyb3VwUHJvcGVydHksXG4gICAgICBkZXNjcmlwdGlvbjogcHJvcHMuZGVzY3JpcHRpb24sXG4gICAgICAvL3RhZ3NcbiAgICB9O1xuXG4gICAgY29uc3QgcmVzb3VyY2U6Q2ZuUnVsZUdyb3VwID0gbmV3IENmblJ1bGVHcm91cCh0aGlzLCBpZCwgcmVzb3VyY2VQcm9wcyk7XG5cbiAgICB0aGlzLnJ1bGVHcm91cElkID0gdGhpcy5nZXRSZXNvdXJjZU5hbWVBdHRyaWJ1dGUocmVzb3VyY2UucmVmKTtcbiAgICB0aGlzLnJ1bGVHcm91cEFybiA9IHRoaXMuZ2V0UmVzb3VyY2VBcm5BdHRyaWJ1dGUocmVzb3VyY2UuYXR0clJ1bGVHcm91cEFybiwge1xuICAgICAgc2VydmljZTogJ05ldHdvcmtGaXJld2FsbCcsXG4gICAgICByZXNvdXJjZTogJ1J1bGVHcm91cCcsXG4gICAgICByZXNvdXJjZU5hbWU6IHRoaXMucnVsZUdyb3VwSWQsXG4gICAgfSk7XG4gIH1cbn1cblxuLyoqXG4gKiBEZWZpbmVzIGEgU3RhdGVmdWwgRG9tYWluIExpc3QgUnVsZSBncm91cCBpbiB0aGUgc3RhY2tcbiAqXG4gKiBAcmVzb3VyY2UgQVdTOjpOZXR3b3JrRklyZXdhbGw6OlJ1bGVHcm91cFxuICovXG5leHBvcnQgaW50ZXJmYWNlIFN0YXRlZnVsRG9tYWluTGlzdFJ1bGVHcm91cFByb3BzIGV4dGVuZHMgU3RhdGVmdWxSdWxlR3JvdXBQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgRG9tYWluIExpc3QgcnVsZVxuICAgKiBAZGVmYXVsdCAtIHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgcnVsZT86IFN0YXRlZnVsRG9tYWluTGlzdFJ1bGU7XG59XG5cbi8qKlxuICogQSBTdGF0ZWZ1bCBSdWxlIGdyb3VwIHRoYXQgaG9sZHMgRG9tYWluIExpc3QgUnVsZXNcbiAqIEByZXNvdXJjZSBBV1M6Ok5ldHdvcmtGaXJld2FsbDo6UnVsZUdyb3VwXG4gKi9cbmV4cG9ydCBjbGFzcyBTdGF0ZWZ1bERvbWFpbkxpc3RSdWxlR3JvdXAgZXh0ZW5kcyBTdGF0ZWZ1bFJ1bGVHcm91cCB7XG5cbiAgcHVibGljIHJlYWRvbmx5IHJ1bGVHcm91cEFybjogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgcnVsZUdyb3VwSWQ6IHN0cmluZztcblxuICBjb25zdHJ1Y3RvcihzY29wZTpDb25zdHJ1Y3QsIGlkOnN0cmluZywgcHJvcHM/OlN0YXRlZnVsRG9tYWluTGlzdFJ1bGVHcm91cFByb3BzKSB7XG4gICAgaWYgKHByb3BzID09PSB1bmRlZmluZWQpIHtwcm9wcyA9IHt9O31cbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIGNvbnN0IHJlc291cmNlU291cmNlUHJvcGVydHk6Q2ZuUnVsZUdyb3VwLlJ1bGVzU291cmNlUHJvcGVydHk9KHByb3BzLnJ1bGUgIT09IHVuZGVmaW5lZCk/XG4gICAgICB7IHJ1bGVzU291cmNlTGlzdDogcHJvcHMucnVsZS5yZXNvdXJjZSB9Ont9O1xuXG4gICAgY29uc3QgcmVzb3VyY2VSdWxlT3B0aW9uczpDZm5SdWxlR3JvdXAuU3RhdGVmdWxSdWxlT3B0aW9uc1Byb3BlcnR5ID0ge1xuICAgICAgcnVsZU9yZGVyOiBwcm9wcy5ydWxlT3JkZXIgfHwgU3RhdGVmdWxSdWxlT3B0aW9ucy5ERUZBVUxUX0FDVElPTl9PUkRFUixcbiAgICB9O1xuXG4gICAgY29uc3QgcmVzb3VyY2VSdWxlR3JvdXBQcm9wZXJ0eTpDZm5SdWxlR3JvdXAuUnVsZUdyb3VwUHJvcGVydHkgPSB7XG4gICAgICBydWxlc1NvdXJjZTogcmVzb3VyY2VTb3VyY2VQcm9wZXJ0eSxcbiAgICAgIHJ1bGVWYXJpYWJsZXM6IHByb3BzLnZhcmlhYmxlcyB8fCB7fSxcbiAgICAgIHN0YXRlZnVsUnVsZU9wdGlvbnM6IHJlc291cmNlUnVsZU9wdGlvbnMsXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlUHJvcHM6Q2ZuUnVsZUdyb3VwUHJvcHM9e1xuICAgICAgY2FwYWNpdHk6IHByb3BzLmNhcGFjaXR5IHx8IDEwMCxcbiAgICAgIHJ1bGVHcm91cE5hbWU6IHByb3BzLnJ1bGVHcm91cE5hbWUgfHwgaWQsXG4gICAgICB0eXBlOiBSdWxlR3JvdXBUeXBlLlNUQVRFRlVMLFxuICAgICAgcnVsZUdyb3VwOiByZXNvdXJjZVJ1bGVHcm91cFByb3BlcnR5LFxuICAgICAgZGVzY3JpcHRpb246IHByb3BzLmRlc2NyaXB0aW9uLFxuICAgICAgLy90YWdzXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlOkNmblJ1bGVHcm91cCA9IG5ldyBDZm5SdWxlR3JvdXAodGhpcywgaWQsIHJlc291cmNlUHJvcHMpO1xuICAgIHRoaXMucnVsZUdyb3VwSWQgPSB0aGlzLmdldFJlc291cmNlTmFtZUF0dHJpYnV0ZShyZXNvdXJjZS5yZWYpO1xuICAgIHRoaXMucnVsZUdyb3VwQXJuID0gdGhpcy5nZXRSZXNvdXJjZUFybkF0dHJpYnV0ZShyZXNvdXJjZS5hdHRyUnVsZUdyb3VwQXJuLCB7XG4gICAgICBzZXJ2aWNlOiAnTmV0d29ya0ZpcmV3YWxsJyxcbiAgICAgIHJlc291cmNlOiAnUnVsZUdyb3VwJyxcbiAgICAgIHJlc291cmNlTmFtZTogdGhpcy5ydWxlR3JvdXBJZCxcbiAgICB9KTtcbiAgfVxufVxuIl19