"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FirewallPolicy = void 0;
const actions_1 = require("./actions");
const aws_networkfirewall_1 = require("aws-cdk-lib/aws-networkfirewall");
const core = require("aws-cdk-lib/core");
class FirewallPolicyBase extends core.Resource {
}
/**
 * Defines a Firewall Policy in the stack
 * @resource AWS::NetworkFirewall::FirewallPolicy
 */
class FirewallPolicy extends FirewallPolicyBase {
    /**
     * Reference existing firewall policy name
     * @param firewallPolicyName The name of the existing firewall policy
     */
    static fromFirewallPolicyName(scope, id, firewallPolicyName) {
        class Import extends FirewallPolicyBase {
            constructor() {
                super(...arguments);
                this.firewallPolicyId = firewallPolicyName;
                this.firewallPolicyArn = core.Stack.of(scope).formatArn({
                    service: 'network-firewall',
                    resource: 'firewall-policy',
                    resourceName: firewallPolicyName,
                });
            }
        }
        return new Import(scope, id);
    }
    /**
     * Reference existing firewall policy by Arn
     * @param firewallPolicyArn the ARN of the existing firewall policy
     */
    static fromFirewallPolicyArn(scope, id, firewallPolicyArn) {
        class Import extends FirewallPolicyBase {
            constructor() {
                super(...arguments);
                this.firewallPolicyId = core.Fn.select(1, core.Fn.split('/', firewallPolicyArn));
                this.firewallPolicyArn = firewallPolicyArn;
            }
        }
        return new Import(scope, id);
    }
    constructor(scope, id, props) {
        super(scope, id, {
            physicalName: props.firewallPolicyName,
        });
        /**
         * The Default actions for packets that don't match a stateless rule
         */
        this.statelessDefaultActions = [];
        /**
         * The Default actions for fragment packets that don't match a stateless rule
         */
        this.statelessFragmentDefaultActions = [];
        /**
         * The Default actions for packets that don't match a stateful rule
         */
        this.statefulDefaultActions = [];
        /**
         * The stateless rule groups in this policy
         */
        this.statelessRuleGroups = [];
        /**
         * The stateful rule groups in this policy
         */
        this.statefulRuleGroups = [];
        this.statelessDefaultActions = props.statelessDefaultActions || [];
        this.statelessFragmentDefaultActions = props.statelessFragmentDefaultActions || [];
        this.statefulDefaultActions = props.statefulDefaultActions || [];
        this.statelessRuleGroups = props.statelessRuleGroups || [];
        this.statefulRuleGroups = props.statefulRuleGroups || [];
        // Adding Validations
        /**
         * Validate policyId
         */
        if (props.firewallPolicyName !== undefined) {
            if (/^[a-zA-Z0-9-]+$/.test(props.firewallPolicyName)) {
                this.firewallPolicyId = props.firewallPolicyName;
            }
            else {
                throw new Error('firewallPolicyName must contain only letters, numbers, and dashes, ' +
                    `got: '${props.firewallPolicyName}'`);
            }
        }
        /**
         * Validating Stateless Default Actions
         */
        if (props.statelessDefaultActions !== undefined) {
            // Ensure only one standard action is provided.
            if (this.validateOnlyOne(actions_1.StatelessStandardAction, props.statelessDefaultActions)) {
                this.statelessDefaultActions = props.statelessDefaultActions;
            }
            else {
                throw new Error('Only one standard action can be provided for the StatelessDefaultAction, all other actions must be custom');
            }
        }
        /**
         * Validating Stateless Fragement Default Actions
         */
        if (props.statelessFragmentDefaultActions !== undefined) {
            // Ensure only one standard action is provided.
            if (this.validateOnlyOne(actions_1.StatelessStandardAction, props.statelessFragmentDefaultActions)) {
                this.statelessFragmentDefaultActions = props.statelessFragmentDefaultActions;
            }
            else {
                throw new Error('Only one standard action can be provided for the StatelessFragementDefaultAction, all other actions must be custom');
            }
        }
        /**
         * Validating Stateful Strict Default Actions
         */
        if (props.statefulDefaultActions !== undefined) {
            // Ensure only one standard action is provided.
            if (this.validateOnlyOne(actions_1.StatefulStrictAction, props.statefulDefaultActions)) {
                this.statefulDefaultActions = props.statefulDefaultActions;
            }
            else {
                throw new Error('Only one strict action can be provided for the StatefulDefaultAction, all other actions must be custom');
            }
        }
        /**
         * validate unique stateless group priorities
         */
        if (props.statelessRuleGroups !== undefined) {
            if (!this.validateUniquePriority(props.statelessRuleGroups)) {
                throw new Error('Priority must be unique, recieved duplicate priority on stateless group');
            }
            //this.statelessRuleGroupReferences = this.buildRuleGroupReferences(props.statelessRuleGroups);
        }
        (props.statelessRuleGroups || []).forEach(ruleGroup => this.addStatelessRuleGroup.bind(ruleGroup));
        /**
         * validate unique stateful group priorities
         */
        if (props.statefulRuleGroups !== undefined) {
            if (!this.validateUniquePriority(props.statefulRuleGroups)) {
                throw new Error('Priority must be unique, recieved duplicate priority on stateful group');
            }
            //this.statefulRuleGroupReferences = this.buildRuleGroupReferences(props.statefulRuleGroups);
        }
        (props.statefulRuleGroups || []).forEach(ruleGroup => this.addStatefulRuleGroup.bind(ruleGroup));
        // Auto define stateless default actions?
        //const statelessDefaultActions = props.statelessDefaultActions || [StatelessStandardAction.DROP];
        // Auto define stateless fragement default actions?
        //const statelessFragmentDefaultActions = props.statelessFragmentDefaultActions || [StatelessStandardAction.DROP];
        // Auto define stateful default actions?
        // Only valid when using the strict order rule
        //const statefulDefaultActions = props.statefulDefaultActions || [statefulStrictAction.ALERT_ESTABLISHED]
        // Auto define stateless rule group?
        //const statelessRuleGroup = props.statelessRuleGroups || [new StatelessRuleGroup(priority=10,...)];
        // Auto define stateful rule group?
        //const statefulRuleGroup = props.statefulRuleGroups || [new StatefulRuleGroup5Tuple(priority=10,...)];
        const resourcePolicyProperty = {
            statelessDefaultActions: this.statelessDefaultActions,
            statelessFragmentDefaultActions: this.statelessFragmentDefaultActions,
            // The properties below are optional.
            statefulDefaultActions: this.statefulDefaultActions,
            statefulEngineOptions: props.statefulEngineOptions,
            statefulRuleGroupReferences: core.Lazy.any({ produce: () => this.buildStatefulRuleGroupReferences() }),
            statelessCustomActions: props.statelessCustomActions,
            statelessRuleGroupReferences: core.Lazy.any({ produce: () => this.buildStatelessRuleGroupReferences() }),
        };
        const resourceProps = {
            firewallPolicy: resourcePolicyProperty,
            firewallPolicyName: props.firewallPolicyName || id,
            description: props.description,
            //TODO tags
        };
        const resource = new aws_networkfirewall_1.CfnFirewallPolicy(this, props.firewallPolicyName || id, resourceProps);
        this.firewallPolicyId = this.getResourceNameAttribute(resource.ref);
        this.firewallPolicyArn = this.getResourceArnAttribute(resource.attrFirewallPolicyArn, {
            service: 'NetworkFirewall',
            resource: 'FirewallPolicy',
            resourceName: this.firewallPolicyId,
        });
    }
    /**
     * Add a stateless rule group to the policy
     *
     * @param ruleGroup The stateless rule group to add to the policy
     */
    addStatelessRuleGroup(ruleGroup) {
        this.statelessRuleGroups.push(ruleGroup);
    }
    /**
     * Add a stateful rule group to the policy
     *
     * @param ruleGroup The stateful rule group to add to the policy
     */
    addStatefulRuleGroup(ruleGroup) {
        this.statefulRuleGroups.push(ruleGroup);
    }
    /**
     * Builds the stateless rule group list object from current state
     * uses this.buildRuleGroupReferences
     */
    buildStatelessRuleGroupReferences() {
        let ruleGroupReferences = [];
        let ruleGroup;
        for (ruleGroup of this.statelessRuleGroups) {
            ruleGroupReferences.push({
                priority: ruleGroup.priority,
                resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
            });
        }
        return ruleGroupReferences;
    }
    /**
     * Builds the stateful rule group list object from current state
     * uses this.buildRuleGroupReferences
     */
    buildStatefulRuleGroupReferences() {
        let ruleGroupReferences = [];
        let ruleGroup;
        for (ruleGroup of this.statefulRuleGroups) {
            if (ruleGroup.priority !== undefined) {
                ruleGroupReferences.push({
                    priority: ruleGroup.priority,
                    resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
                });
            }
            else {
                ruleGroupReferences.push({
                    resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
                });
            }
        }
        return ruleGroupReferences;
    }
    /**
     * Converts a Stateful(less)RuleGroupList to a Stateful(less)RuleGroupReferenceProperty
     */
    /*private buildRuleGroupReferences(ruleGroups:(StatefulRuleGroupList|StatelessRuleGroupList)[]) {
      let ruleGroupReferences:CfnFirewallPolicy.StatelessRuleGroupReferenceProperty[]|CfnFirewallPolicy.StatefulRuleGroupReferenceProperty = [];
      let ruleGroup:StatefulRuleGroupList|StatelessRuleGroupList;
      for (ruleGroup of ruleGroups) {
        ruleGroupReferences.push({
          priority: ruleGroup.priority,
          resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
        });
      }
      return ruleGroupReferences;
    }*/
    /**
     * To validate a set of rule groups to ensure they have unqiue priorities
     */
    validateUniquePriority(ruleGroups) {
        let priorities = [];
        let ruleGroup;
        for (ruleGroup of ruleGroups) {
            // priorities are only required when using strict order evaulation.
            // Don't check undefined priorites, as the priority can be
            // determined implicitly.
            if (ruleGroup.priority !== undefined) {
                if (priorities.includes(ruleGroup.priority)) {
                    return false;
                }
                priorities.push(ruleGroup.priority);
            }
        }
        return true;
    }
    /**
     * Validates that only one occurance of the enumeration is found in the values.
     * This is for verifying only one standard default action is used in a list.
     */
    validateOnlyOne(enumeration, values) {
        let oneFound = false;
        let value;
        for (value of values) {
            if (Object.values(enumeration).includes(value)) {
                if (oneFound) {
                    return false;
                }
                oneFound = true;
            }
        }
        return true;
    }
}
exports.FirewallPolicy = FirewallPolicy;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicG9saWN5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsicG9saWN5LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUNBLHVDQUEwRTtBQUMxRSx5RUFBNEY7QUFFNUYseUNBQXlDO0FBcUR6QyxNQUFlLGtCQUFtQixTQUFRLElBQUksQ0FBQyxRQUFRO0NBY3REO0FBcUVEOzs7R0FHRztBQUNILE1BQWEsY0FBZSxTQUFRLGtCQUFrQjtJQUNwRDs7O09BR0c7SUFDSSxNQUFNLENBQUMsc0JBQXNCLENBQUMsS0FBZ0IsRUFBRSxFQUFTLEVBQUUsa0JBQTBCO1FBQzFGLE1BQU0sTUFBTyxTQUFRLGtCQUFrQjtZQUF2Qzs7Z0JBQ2tCLHFCQUFnQixHQUFHLGtCQUFrQixDQUFDO2dCQUN0QyxzQkFBaUIsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQyxLQUFLLENBQUMsQ0FBQyxTQUFTLENBQUM7b0JBQ2pFLE9BQU8sRUFBRSxrQkFBa0I7b0JBQzNCLFFBQVEsRUFBRSxpQkFBaUI7b0JBQzNCLFlBQVksRUFBRSxrQkFBa0I7aUJBQ2pDLENBQUMsQ0FBQztZQUNMLENBQUM7U0FBQTtRQUNELE9BQU8sSUFBSSxNQUFNLENBQUMsS0FBSyxFQUFFLEVBQUUsQ0FBQyxDQUFDO0lBQy9CLENBQUM7SUFFRDs7O09BR0c7SUFDSSxNQUFNLENBQUMscUJBQXFCLENBQUMsS0FBZ0IsRUFBRSxFQUFTLEVBQUUsaUJBQXlCO1FBQ3hGLE1BQU0sTUFBTyxTQUFRLGtCQUFrQjtZQUF2Qzs7Z0JBQ2tCLHFCQUFnQixHQUFHLElBQUksQ0FBQyxFQUFFLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxJQUFJLENBQUMsRUFBRSxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUsaUJBQWlCLENBQUMsQ0FBQyxDQUFDO2dCQUM1RSxzQkFBaUIsR0FBRyxpQkFBaUIsQ0FBQTtZQUN2RCxDQUFDO1NBQUE7UUFDRCxPQUFPLElBQUksTUFBTSxDQUFDLEtBQUssRUFBRSxF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USxLQUFLLFNBQVMsRUFBRTtnQkFDcEMsSUFBSSxVQUFVLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsRUFBRTtvQkFDM0MsT0FBTyxLQUFLLENBQUM7aUJBQ2Q7Z0JBQ0QsVUFBVSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDLENBQUM7YUFDckM7U0FDRjtRQUNELE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQztJQUVEOzs7T0FHRztJQUNLLGVBQWUsQ0FBQyxXQUFlLEVBQUUsTUFBZTtRQUN0RCxJQUFJLFFBQVEsR0FBVyxLQUFLLENBQUM7UUFDN0IsSUFBSSxLQUFZLENBQUM7UUFDakIsS0FBSyxLQUFLLElBQUksTUFBTSxFQUFFO1lBQ3BCLElBQUksTUFBTSxDQUFDLE1BQU0sQ0FBUyxXQUFXLENBQUMsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLEVBQUU7Z0JBQ3RELElBQUksUUFBUSxFQUFFO29CQUNaLE9BQU8sS0FBSyxDQUFDO2lCQUNkO2dCQUNELFFBQVEsR0FBRyxJQUFJLENBQUM7YUFDakI7U0FDRjtRQUNELE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQztDQUNGO0FBdlNELHdDQXVTQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gJ2NvbnN0cnVjdHMnO1xuaW1wb3J0IHsgU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24sIFN0YXRlZnVsU3RyaWN0QWN0aW9uIH0gZnJvbSAnLi9hY3Rpb25zJztcbmltcG9ydCB7IENmbkZpcmV3YWxsUG9saWN5LCBDZm5GaXJld2FsbFBvbGljeVByb3BzIH0gZnJvbSAnYXdzLWNkay1saWIvYXdzLW5ldHdvcmtmaXJld2FsbCc7XG5pbXBvcnQgeyBJU3RhdGVmdWxSdWxlR3JvdXAsIElTdGF0ZWxlc3NSdWxlR3JvdXAgfSBmcm9tICcuL3J1bGUtZ3JvdXAnO1xuaW1wb3J0ICogYXMgY29yZSBmcm9tICdhd3MtY2RrLWxpYi9jb3JlJztcblxuLyoqXG4gKiAgTWFwcyBhIHByaW9yaXR5IHRvIGEgc3RhdGVmdWwgcnVsZSBncm91cCBpdGVtXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgU3RhdGVmdWxSdWxlR3JvdXBMaXN0IHtcbiAgLyoqXG4gICAqIFRoZSBwcmlvcml0eSBvZiB0aGUgcnVsZSBncm91cCBpbiB0aGUgcG9saWN5XG4gICAqIEBkZWZhdWx0IC0gUHJpb3JpdHkgaXMgb25seSB1c2VkIHdoZW4gU3RyaWN0IG9yZGVyIGlzIHNldC5cbiAgICovXG4gIHJlYWRvbmx5IHByaW9yaXR5PzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBUaGUgc3RhdGVmdWwgcnVsZSBncm91cFxuICAgKi9cbiAgcmVhZG9ubHkgcnVsZUdyb3VwOiBJU3RhdGVmdWxSdWxlR3JvdXA7XG59XG5cbi8qKlxuICogTWFwcyBhIHByaW9yaXR5IHRvIGEgc3RhdGVsZXNzIHJ1bGUgZ3JvdXAgaXRlbVxuICovXG5leHBvcnQgaW50ZXJmYWNlIFN0YXRlbGVzc1J1bGVHcm91cExpc3Qge1xuICAvKipcbiAgICogVGhlIHByaW9yaXR5IG9mIHRoZSBydWxlIGdyb3VwIGluIHRoZSBwb2xpY3lcbiAgICovXG4gIHJlYWRvbmx5IHByaW9yaXR5OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIFRoZSBzdGF0ZWxlc3MgcnVsZVxuICAgKi9cbiAgcmVhZG9ubHkgcnVsZUdyb3VwOiBJU3RhdGVsZXNzUnVsZUdyb3VwO1xufVxuXG4vKipcbiAqIERlZmluZXMgYSBOZXR3b3JrIEZpcmV3YWxsIFBvbGljeSBpbiB0aGUgc3RhY2tcbiAqL1xuZXhwb3J0IGludGVyZmFjZSBJRmlyZXdhbGxQb2xpY3kgZXh0ZW5kcyBjb3JlLklSZXNvdXJjZSB7XG4gIC8qKlxuICAgKiBUaGUgQXJuIG9mIHRoZSBwb2xpY3kuXG4gICAqXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5QXJuOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBwaHlpc2NhbCBuYW1lIG9mIHRoZSBmaXJld2FsbCBwb2xpY3kuXG4gICAqXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5SWQ6IHN0cmluZztcblxufVxuXG5hYnN0cmFjdCBjbGFzcyBGaXJld2FsbFBvbGljeUJhc2UgZXh0ZW5kcyBjb3JlLlJlc291cmNlIGltcGxlbWVudHMgSUZpcmV3YWxsUG9saWN5IHtcbiAgLyoqXG4gICAqIFRoZSBBcm4gb2YgdGhlIHBvbGljeS5cbiAgICpcbiAgICogQGF0dHJpYnV0ZVxuICAgKi9cbiAgcHVibGljIGFic3RyYWN0IHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5QXJuOiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBwaHlpc2NhbCBuYW1lIG9mIHRoZSBmaXJld2FsbCBwb2xpY3kuXG4gICAqXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCByZWFkb25seSBmaXJld2FsbFBvbGljeUlkOiBzdHJpbmc7XG59XG5cbi8qKlxuICogVGhlIFByb3BlcnRpZXMgZm9yIGRlZmluaW5nIGEgRmlyZXdhbGwgcG9saWN5XG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRmlyZXdhbGxQb2xpY3lQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgZGVzY3JpcHRpdmUgbmFtZSBvZiB0aGUgZmlyZXdhbGwgcG9saWN5LlxuICAgKiBZb3UgY2FuJ3QgY2hhbmdlIHRoZSBuYW1lIG9mIGEgZmlyZXdhbGwgcG9saWN5IGFmdGVyIHlvdSBjcmVhdGUgaXQuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gQ2xvdWRGb3JtYXRpb24tZ2VuZXJhdGVkIG5hbWVcbiAgICovXG4gIHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5TmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIGFjdGlvbnMgdG8gdGFrZSBvbiBhIHBhY2tldCBpZiBpdCBkb2Vzbid0IG1hdGNoIGFueSBvZiB0aGUgc3RhdGVsZXNzIHJ1bGVzIGluIHRoZSBwb2xpY3kuXG4gICAqL1xuICByZWFkb25seSBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogKFN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uIHwgc3RyaW5nKVtdO1xuXG4gIC8qKlxuICAgKiBUaGUgYWN0aW9ucyB0byB0YWtlIG9uIGEgZnJhZ21lbnRlZCBwYWNrZXQgaWYgaXQgZG9lc24ndCBtYXRjaCBhbnkgb2YgdGhlIHN0YXRlbGVzcyBydWxlcyBpbiB0aGUgcG9saWN5LlxuICAgKi9cbiAgcmVhZG9ubHkgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogKFN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uIHwgc3RyaW5nKVtdO1xuXG4gIC8qKlxuICAgKiBUaGUgZGVmYXVsdCBhY3Rpb25zIHRvIHRha2Ugb24gYSBwYWNrZXQgdGhhdCBkb2Vzbid0IG1hdGNoIGFueSBzdGF0ZWZ1bCBydWxlcy5cbiAgICogVGhlIHN0YXRlZnVsIGRlZmF1bHQgYWN0aW9uIGlzIG9wdGlvbmFsLCBhbmQgaXMgb25seSB2YWxpZCB3aGVuIHVzaW5nIHRoZSBzdHJpY3QgcnVsZSBvcmRlclxuICAgKlxuICAgKiBAZGVmYXVsdCAtIHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgc3RhdGVmdWxEZWZhdWx0QWN0aW9ucz86IChTdGF0ZWZ1bFN0cmljdEFjdGlvbiB8IHN0cmluZylbXTtcblxuICAvKipcbiAgICogQWRkaXRpb25hbCBvcHRpb25zIGdvdmVybmluZyBob3cgTmV0d29yayBGaXJld2FsbCBoYW5kbGVzIHN0YXRlZnVsIHJ1bGVzLlxuICAgKiBUaGUgc3RhdGVmdWwgcnVsZSBncm91cHMgdGhhdCB5b3UgdXNlIGluIHlvdXIgcG9saWN5IG11c3QgaGF2ZSBzdGF0ZWZ1bCBydWxlIG9wdGlvbnMgc2V0dGluZ3MgdGhhdCBhcmUgY29tcGF0aWJsZSB3aXRoIHRoZXNlIHNldHRpbmdzXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSBzdGF0ZWZ1bEVuZ2luZU9wdGlvbnM/OiBDZm5GaXJld2FsbFBvbGljeS5TdGF0ZWZ1bEVuZ2luZU9wdGlvbnNQcm9wZXJ0eTtcblxuICAvKipcbiAgICogVGhlIHN0YXRlZnVsIHJ1bGUgZ3JvdXBzIHRoYXQgYXJlIHVzZWQgaW4gdGhlIHBvbGljeS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSB1bmRlZmluZWRcbiAgICovXG4gIHJlYWRvbmx5IHN0YXRlZnVsUnVsZUdyb3Vwcz86IFN0YXRlZnVsUnVsZUdyb3VwTGlzdFtdO1xuXG4gIC8qKlxuICAgKiBUaGUgY3VzdG9tIGFjdGlvbiBkZWZpbml0aW9ucyB0aGF0IGFyZSBhdmFpbGFibGUgZm9yIHVzZSBpbiB0aGUgZmlyZXdhbGwgcG9saWN5J3Mgc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnMgc2V0dGluZy5cbiAgICpcbiAgICogQGRlZmF1bHQgLSB1bmRlZmluZWRcbiAgICovXG4gIHJlYWRvbmx5IHN0YXRlbGVzc0N1c3RvbUFjdGlvbnM/OiBDZm5GaXJld2FsbFBvbGljeS5DdXN0b21BY3Rpb25Qcm9wZXJ0eVtdO1xuXG4gIC8qKlxuICAgKlJlZmVyZW5jZXMgdG8gdGhlIHN0YXRlbGVzcyBydWxlIGdyb3VwcyB0aGF0IGFyZSB1c2VkIGluIHRoZSBwb2xpY3kuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSBzdGF0ZWxlc3NSdWxlR3JvdXBzPzogU3RhdGVsZXNzUnVsZUdyb3VwTGlzdFtdO1xuXG4gIC8qKlxuICAgKiBUaGUgZGVzY3JpcHRpb24gb2YgdGhlIHBvbGljeS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSB1bmRlZmluZWRcbiAgICovXG4gIHJlYWRvbmx5IGRlc2NyaXB0aW9uPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIERlZmluZXMgYSBGaXJld2FsbCBQb2xpY3kgaW4gdGhlIHN0YWNrXG4gKiBAcmVzb3VyY2UgQVdTOjpOZXR3b3JrRmlyZXdhbGw6OkZpcmV3YWxsUG9saWN5XG4gKi9cbmV4cG9ydCBjbGFzcyBGaXJld2FsbFBvbGljeSBleHRlbmRzIEZpcmV3YWxsUG9saWN5QmFzZSB7XG4gIC8qKlxuICAgKiBSZWZlcmVuY2UgZXhpc3RpbmcgZmlyZXdhbGwgcG9saWN5IG5hbWVcbiAgICogQHBhcmFtIGZpcmV3YWxsUG9saWN5TmFtZSBUaGUgbmFtZSBvZiB0aGUgZXhpc3RpbmcgZmlyZXdhbGwgcG9saWN5XG4gICAqL1xuICBwdWJsaWMgc3RhdGljIGZyb21GaXJld2FsbFBvbGljeU5hbWUoc2NvcGU6IENvbnN0cnVjdCwgaWQ6c3RyaW5nLCBmaXJld2FsbFBvbGljeU5hbWU6IHN0cmluZyk6IElGaXJld2FsbFBvbGljeSB7XG4gICAgY2xhc3MgSW1wb3J0IGV4dGVuZHMgRmlyZXdhbGxQb2xpY3lCYXNlIHtcbiAgICAgIHB1YmxpYyByZWFkb25seSBmaXJld2FsbFBvbGljeUlkID0gZmlyZXdhbGxQb2xpY3lOYW1lO1xuICAgICAgcHVibGljIHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5QXJuID0gY29yZS5TdGFjay5vZihzY29wZSkuZm9ybWF0QXJuKHtcbiAgICAgICAgc2VydmljZTogJ25ldHdvcmstZmlyZXdhbGwnLFxuICAgICAgICByZXNvdXJjZTogJ2ZpcmV3YWxsLXBvbGljeScsXG4gICAgICAgIHJlc291cmNlTmFtZTogZmlyZXdhbGxQb2xpY3lOYW1lLFxuICAgICAgfSk7XG4gICAgfVxuICAgIHJldHVybiBuZXcgSW1wb3J0KHNjb3BlLCBpZCk7XG4gIH1cblxuICAvKipcbiAgICogUmVmZXJlbmNlIGV4aXN0aW5nIGZpcmV3YWxsIHBvbGljeSBieSBBcm5cbiAgICogQHBhcmFtIGZpcmV3YWxsUG9saWN5QXJuIHRoZSBBUk4gb2YgdGhlIGV4aXN0aW5nIGZpcmV3YWxsIHBvbGljeVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBmcm9tRmlyZXdhbGxQb2xpY3lBcm4oc2NvcGU6IENvbnN0cnVjdCwgaWQ6c3RyaW5nLCBmaXJld2FsbFBvbGljeUFybjogc3RyaW5nKTogSUZpcmV3YWxsUG9saWN5IHtcbiAgICBjbGFzcyBJbXBvcnQgZXh0ZW5kcyBGaXJld2FsbFBvbGljeUJhc2Uge1xuICAgICAgcHVibGljIHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5SWQgPSBjb3JlLkZuLnNlbGVjdCgxLCBjb3JlLkZuLnNwbGl0KCcvJywgZmlyZXdhbGxQb2xpY3lBcm4pKTtcbiAgICAgIHB1YmxpYyByZWFkb25seSBmaXJld2FsbFBvbGljeUFybiA9IGZpcmV3YWxsUG9saWN5QXJuXG4gICAgfVxuICAgIHJldHVybiBuZXcgSW1wb3J0KHNjb3BlLCBpZCk7XG4gIH1cblxuICBwdWJsaWMgcmVhZG9ubHkgZmlyZXdhbGxQb2xpY3lBcm46IHN0cmluZztcbiAgcHVibGljIHJlYWRvbmx5IGZpcmV3YWxsUG9saWN5SWQ6IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIERlZmF1bHQgYWN0aW9ucyBmb3IgcGFja2V0cyB0aGF0IGRvbid0IG1hdGNoIGEgc3RhdGVsZXNzIHJ1bGVcbiAgICovXG4gIHB1YmxpYyByZWFkb25seSBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogc3RyaW5nW10gPSBbXTtcblxuICAvKipcbiAgICogVGhlIERlZmF1bHQgYWN0aW9ucyBmb3IgZnJhZ21lbnQgcGFja2V0cyB0aGF0IGRvbid0IG1hdGNoIGEgc3RhdGVsZXNzIHJ1bGVcbiAgICovXG4gIHB1YmxpYyByZWFkb25seSBzdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zOiBzdHJpbmdbXSA9IFtdO1xuXG4gIC8qKlxuICAgKiBUaGUgRGVmYXVsdCBhY3Rpb25zIGZvciBwYWNrZXRzIHRoYXQgZG9uJ3QgbWF0Y2ggYSBzdGF0ZWZ1bCBydWxlXG4gICAqL1xuICBwdWJsaWMgcmVhZG9ubHkgc3RhdGVmdWxEZWZhdWx0QWN0aW9uczogc3RyaW5nW10gPSBbXTtcblxuICAvKipcbiAgICogVGhlIHN0YXRlbGVzcyBydWxlIGdyb3VwcyBpbiB0aGlzIHBvbGljeVxuICAgKi9cbiAgcHVibGljIHJlYWRvbmx5IHN0YXRlbGVzc1J1bGVHcm91cHM6IFN0YXRlbGVzc1J1bGVHcm91cExpc3RbXSA9IFtdO1xuXG4gIC8qKlxuICAgKiBUaGUgc3RhdGVmdWwgcnVsZSBncm91cHMgaW4gdGhpcyBwb2xpY3lcbiAgICovXG4gIHB1YmxpYyByZWFkb25seSBzdGF0ZWZ1bFJ1bGVHcm91cHM6IFN0YXRlZnVsUnVsZUdyb3VwTGlzdFtdID0gW107XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6Q29uc3RydWN0LCBpZDpzdHJpbmcsIHByb3BzOiBGaXJld2FsbFBvbGljeVByb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkLCB7XG4gICAgICBwaHlzaWNhbE5hbWU6IHByb3BzLmZpcmV3YWxsUG9saWN5TmFtZSxcbiAgICB9KTtcblxuICAgIHRoaXMuc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnMgPSBwcm9wcy5zdGF0ZWxlc3NEZWZhdWx0QWN0aW9ucyB8fCBbXTtcbiAgICB0aGlzLnN0YXRlbGVzc0ZyYWdtZW50RGVmYXVsdEFjdGlvbnMgPSBwcm9wcy5zdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zIHx8IFtdO1xuICAgIHRoaXMuc3RhdGVmdWxEZWZhdWx0QWN0aW9ucyA9IHByb3BzLnN0YXRlZnVsRGVmYXVsdEFjdGlvbnMgfHwgW107XG5cbiAgICB0aGlzLnN0YXRlbGVzc1J1bGVHcm91cHMgPSBwcm9wcy5zdGF0ZWxlc3NSdWxlR3JvdXBzIHx8IFtdO1xuICAgIHRoaXMuc3RhdGVmdWxSdWxlR3JvdXBzID0gcHJvcHMuc3RhdGVmdWxSdWxlR3JvdXBzIHx8IFtdO1xuXG4gICAgLy8gQWRkaW5nIFZhbGlkYXRpb25zXG5cbiAgICAvKipcbiAgICAgKiBWYWxpZGF0ZSBwb2xpY3lJZFxuICAgICAqL1xuICAgIGlmIChwcm9wcy5maXJld2FsbFBvbGljeU5hbWUgIT09IHVuZGVmaW5lZCkge1xuICAgICAgaWYgKC9eW2EtekEtWjAtOS1dKyQvLnRlc3QocHJvcHMuZmlyZXdhbGxQb2xpY3lOYW1lKSkge1xuICAgICAgICB0aGlzLmZpcmV3YWxsUG9saWN5SWQgPSBwcm9wcy5maXJld2FsbFBvbGljeU5hbWU7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ2ZpcmV3YWxsUG9saWN5TmFtZSBtdXN0IGNvbnRhaW4gb25seSBsZXR0ZXJzLCBudW1iZXJzLCBhbmQgZGFzaGVzLCAnICtcblx0XHQgIGBnb3Q6ICcke3Byb3BzLmZpcmV3YWxsUG9saWN5TmFtZX0nYCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmFsaWRhdGluZyBTdGF0ZWxlc3MgRGVmYXVsdCBBY3Rpb25zXG4gICAgICovXG4gICAgaWYgKHByb3BzLnN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIC8vIEVuc3VyZSBvbmx5IG9uZSBzdGFuZGFyZCBhY3Rpb24gaXMgcHJvdmlkZWQuXG4gICAgICBpZiAodGhpcy52YWxpZGF0ZU9ubHlPbmUoU3RhdGVsZXNzU3RhbmRhcmRBY3Rpb24sIHByb3BzLnN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zKSkge1xuICAgICAgICB0aGlzLnN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zID0gcHJvcHMuc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ09ubHkgb25lIHN0YW5kYXJkIGFjdGlvbiBjYW4gYmUgcHJvdmlkZWQgZm9yIHRoZSBTdGF0ZWxlc3NEZWZhdWx0QWN0aW9uLCBhbGwgb3RoZXIgYWN0aW9ucyBtdXN0IGJlIGN1c3RvbScpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZhbGlkYXRpbmcgU3RhdGVsZXNzIEZyYWdlbWVudCBEZWZhdWx0IEFjdGlvbnNcbiAgICAgKi9cbiAgICBpZiAocHJvcHMuc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9ucyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyBFbnN1cmUgb25seSBvbmUgc3RhbmRhcmQgYWN0aW9uIGlzIHByb3ZpZGVkLlxuICAgICAgaWYgKHRoaXMudmFsaWRhdGVPbmx5T25lKFN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLCBwcm9wcy5zdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zKSkge1xuICAgICAgICB0aGlzLnN0YXRlbGVzc0ZyYWdtZW50RGVmYXVsdEFjdGlvbnMgPSBwcm9wcy5zdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdPbmx5IG9uZSBzdGFuZGFyZCBhY3Rpb24gY2FuIGJlIHByb3ZpZGVkIGZvciB0aGUgU3RhdGVsZXNzRnJhZ2VtZW50RGVmYXVsdEFjdGlvbiwgYWxsIG90aGVyIGFjdGlvbnMgbXVzdCBiZSBjdXN0b20nKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWYWxpZGF0aW5nIFN0YXRlZnVsIFN0cmljdCBEZWZhdWx0IEFjdGlvbnNcbiAgICAgKi9cbiAgICBpZiAocHJvcHMuc3RhdGVmdWxEZWZhdWx0QWN0aW9ucyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyBFbnN1cmUgb25seSBvbmUgc3RhbmRhcmQgYWN0aW9uIGlzIHByb3ZpZGVkLlxuICAgICAgaWYgKHRoaXMudmFsaWRhdGVPbmx5T25lKFN0YXRlZnVsU3RyaWN0QWN0aW9uLCBwcm9wcy5zdGF0ZWZ1bERlZmF1bHRBY3Rpb25zKSkge1xuICAgICAgICB0aGlzLnN0YXRlZnVsRGVmYXVsdEFjdGlvbnMgPSBwcm9wcy5zdGF0ZWZ1bERlZmF1bHRBY3Rpb25zO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdPbmx5IG9uZSBzdHJpY3QgYWN0aW9uIGNhbiBiZSBwcm92aWRlZCBmb3IgdGhlIFN0YXRlZnVsRGVmYXVsdEFjdGlvbiwgYWxsIG90aGVyIGFjdGlvbnMgbXVzdCBiZSBjdXN0b20nKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiB2YWxpZGF0ZSB1bmlxdWUgc3RhdGVsZXNzIGdyb3VwIHByaW9yaXRpZXNcbiAgICAgKi9cbiAgICBpZiAocHJvcHMuc3RhdGVsZXNzUnVsZUdyb3VwcyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBpZiAoIXRoaXMudmFsaWRhdGVVbmlxdWVQcmlvcml0eShwcm9wcy5zdGF0ZWxlc3NSdWxlR3JvdXBzKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1ByaW9yaXR5IG11c3QgYmUgdW5pcXVlLCByZWNpZXZlZCBkdXBsaWNhdGUgcHJpb3JpdHkgb24gc3RhdGVsZXNzIGdyb3VwJyk7XG4gICAgICB9XG4gICAgICAvL3RoaXMuc3RhdGVsZXNzUnVsZUdyb3VwUmVmZXJlbmNlcyA9IHRoaXMuYnVpbGRSdWxlR3JvdXBSZWZlcmVuY2VzKHByb3BzLnN0YXRlbGVzc1J1bGVHcm91cHMpO1xuICAgIH1cbiAgICAocHJvcHMuc3RhdGVsZXNzUnVsZUdyb3VwcyB8fCBbXSkuZm9yRWFjaChydWxlR3JvdXAgPT4gdGhpcy5hZGRTdGF0ZWxlc3NSdWxlR3JvdXAuYmluZChydWxlR3JvdXApKTtcblxuICAgIC8qKlxuICAgICAqIHZhbGlkYXRlIHVuaXF1ZSBzdGF0ZWZ1bCBncm91cCBwcmlvcml0aWVzXG4gICAgICovXG4gICAgaWYgKHByb3BzLnN0YXRlZnVsUnVsZUdyb3VwcyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBpZiAoIXRoaXMudmFsaWRhdGVVbmlxdWVQcmlvcml0eShwcm9wcy5zdGF0ZWZ1bFJ1bGVHcm91cHMpKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignUHJpb3JpdHkgbXVzdCBiZSB1bmlxdWUsIHJlY2lldmVkIGR1cGxpY2F0ZSBwcmlvcml0eSBvbiBzdGF0ZWZ1bCBncm91cCcpO1xuICAgICAgfVxuICAgICAgLy90aGlzLnN0YXRlZnVsUnVsZUdyb3VwUmVmZXJlbmNlcyA9IHRoaXMuYnVpbGRSdWxlR3JvdXBSZWZlcmVuY2VzKHByb3BzLnN0YXRlZnVsUnVsZUdyb3Vwcyk7XG4gICAgfVxuICAgIChwcm9wcy5zdGF0ZWZ1bFJ1bGVHcm91cHMgfHwgW10pLmZvckVhY2gocnVsZUdyb3VwID0+IHRoaXMuYWRkU3RhdGVmdWxSdWxlR3JvdXAuYmluZChydWxlR3JvdXApKTtcblxuICAgIC8vIEF1dG8gZGVmaW5lIHN0YXRlbGVzcyBkZWZhdWx0IGFjdGlvbnM/XG4gICAgLy9jb25zdCBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9ucyA9IHByb3BzLnN0YXRlbGVzc0RlZmF1bHRBY3Rpb25zIHx8IFtTdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbi5EUk9QXTtcblxuICAgIC8vIEF1dG8gZGVmaW5lIHN0YXRlbGVzcyBmcmFnZW1lbnQgZGVmYXVsdCBhY3Rpb25zP1xuICAgIC8vY29uc3Qgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9ucyA9IHByb3BzLnN0YXRlbGVzc0ZyYWdtZW50RGVmYXVsdEFjdGlvbnMgfHwgW1N0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdO1xuXG4gICAgLy8gQXV0byBkZWZpbmUgc3RhdGVmdWwgZGVmYXVsdCBhY3Rpb25zP1xuICAgIC8vIE9ubHkgdmFsaWQgd2hlbiB1c2luZyB0aGUgc3RyaWN0IG9yZGVyIHJ1bGVcbiAgICAvL2NvbnN0IHN0YXRlZnVsRGVmYXVsdEFjdGlvbnMgPSBwcm9wcy5zdGF0ZWZ1bERlZmF1bHRBY3Rpb25zIHx8IFtzdGF0ZWZ1bFN0cmljdEFjdGlvbi5BTEVSVF9FU1RBQkxJU0hFRF1cblxuICAgIC8vIEF1dG8gZGVmaW5lIHN0YXRlbGVzcyBydWxlIGdyb3VwP1xuICAgIC8vY29uc3Qgc3RhdGVsZXNzUnVsZUdyb3VwID0gcHJvcHMuc3RhdGVsZXNzUnVsZUdyb3VwcyB8fCBbbmV3IFN0YXRlbGVzc1J1bGVHcm91cChwcmlvcml0eT0xMCwuLi4pXTtcblxuICAgIC8vIEF1dG8gZGVmaW5lIHN0YXRlZnVsIHJ1bGUgZ3JvdXA/XG4gICAgLy9jb25zdCBzdGF0ZWZ1bFJ1bGVHcm91cCA9IHByb3BzLnN0YXRlZnVsUnVsZUdyb3VwcyB8fCBbbmV3IFN0YXRlZnVsUnVsZUdyb3VwNVR1cGxlKHByaW9yaXR5PTEwLC4uLildO1xuXG4gICAgY29uc3QgcmVzb3VyY2VQb2xpY3lQcm9wZXJ0eTpDZm5GaXJld2FsbFBvbGljeS5GaXJld2FsbFBvbGljeVByb3BlcnR5ID0ge1xuICAgICAgc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM6IHRoaXMuc3RhdGVsZXNzRGVmYXVsdEFjdGlvbnMsXG4gICAgICBzdGF0ZWxlc3NGcmFnbWVudERlZmF1bHRBY3Rpb25zOiB0aGlzLnN0YXRlbGVzc0ZyYWdtZW50RGVmYXVsdEFjdGlvbnMsXG4gICAgICAvLyBUaGUgcHJvcGVydGllcyBiZWxvdyBhcmUgb3B0aW9uYWwuXG4gICAgICBzdGF0ZWZ1bERlZmF1bHRBY3Rpb25zOiB0aGlzLnN0YXRlZnVsRGVmYXVsdEFjdGlvbnMsXG4gICAgICBzdGF0ZWZ1bEVuZ2luZU9wdGlvbnM6IHByb3BzLnN0YXRlZnVsRW5naW5lT3B0aW9ucyxcbiAgICAgIHN0YXRlZnVsUnVsZUdyb3VwUmVmZXJlbmNlczogY29yZS5MYXp5LmFueSh7IHByb2R1Y2U6ICgpID0+IHRoaXMuYnVpbGRTdGF0ZWZ1bFJ1bGVHcm91cFJlZmVyZW5jZXMoKSB9KSxcbiAgICAgIHN0YXRlbGVzc0N1c3RvbUFjdGlvbnM6IHByb3BzLnN0YXRlbGVzc0N1c3RvbUFjdGlvbnMsXG4gICAgICBzdGF0ZWxlc3NSdWxlR3JvdXBSZWZlcmVuY2VzOiBjb3JlLkxhenkuYW55KHsgcHJvZHVjZTogKCkgPT4gdGhpcy5idWlsZFN0YXRlbGVzc1J1bGVHcm91cFJlZmVyZW5jZXMoKSB9KSxcbiAgICB9O1xuXG4gICAgY29uc3QgcmVzb3VyY2VQcm9wczpDZm5GaXJld2FsbFBvbGljeVByb3BzID0ge1xuICAgICAgZmlyZXdhbGxQb2xpY3k6IHJlc291cmNlUG9saWN5UHJvcGVydHksXG4gICAgICBmaXJld2FsbFBvbGljeU5hbWU6IHByb3BzLmZpcmV3YWxsUG9saWN5TmFtZSB8fCBpZCxcbiAgICAgIGRlc2NyaXB0aW9uOiBwcm9wcy5kZXNjcmlwdGlvbixcbiAgICAgIC8vVE9ETyB0YWdzXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlOkNmbkZpcmV3YWxsUG9saWN5ID0gbmV3IENmbkZpcmV3YWxsUG9saWN5KHRoaXMsIHByb3BzLmZpcmV3YWxsUG9saWN5TmFtZSB8fCBpZCwgcmVzb3VyY2VQcm9wcyk7XG5cbiAgICB0aGlzLmZpcmV3YWxsUG9saWN5SWQgPSB0aGlzLmdldFJlc291cmNlTmFtZUF0dHJpYnV0ZShyZXNvdXJjZS5yZWYpO1xuXG4gICAgdGhpcy5maXJld2FsbFBvbGljeUFybiA9IHRoaXMuZ2V0UmVzb3VyY2VBcm5BdHRyaWJ1dGUocmVzb3VyY2UuYXR0ckZpcmV3YWxsUG9saWN5QXJuLCB7XG4gICAgICBzZXJ2aWNlOiAnTmV0d29ya0ZpcmV3YWxsJyxcbiAgICAgIHJlc291cmNlOiAnRmlyZXdhbGxQb2xpY3knLFxuICAgICAgcmVzb3VyY2VOYW1lOiB0aGlzLmZpcmV3YWxsUG9saWN5SWQsXG4gICAgfSk7XG5cbiAgfVxuXG4gIC8qKlxuICAgKiBBZGQgYSBzdGF0ZWxlc3MgcnVsZSBncm91cCB0byB0aGUgcG9saWN5XG4gICAqXG4gICAqIEBwYXJhbSBydWxlR3JvdXAgVGhlIHN0YXRlbGVzcyBydWxlIGdyb3VwIHRvIGFkZCB0byB0aGUgcG9saWN5XG4gICAqL1xuICBwdWJsaWMgYWRkU3RhdGVsZXNzUnVsZUdyb3VwKHJ1bGVHcm91cDpTdGF0ZWxlc3NSdWxlR3JvdXBMaXN0KSB7XG4gICAgdGhpcy5zdGF0ZWxlc3NSdWxlR3JvdXBzLnB1c2gocnVsZUdyb3VwKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBBZGQgYSBzdGF0ZWZ1bCBydWxlIGdyb3VwIHRvIHRoZSBwb2xpY3lcbiAgICpcbiAgICogQHBhcmFtIHJ1bGVHcm91cCBUaGUgc3RhdGVmdWwgcnVsZSBncm91cCB0byBhZGQgdG8gdGhlIHBvbGljeVxuICAgKi9cbiAgcHVibGljIGFkZFN0YXRlZnVsUnVsZUdyb3VwKHJ1bGVHcm91cDpTdGF0ZWZ1bFJ1bGVHcm91cExpc3QpIHtcbiAgICB0aGlzLnN0YXRlZnVsUnVsZUdyb3Vwcy5wdXNoKHJ1bGVHcm91cCk7XG4gIH1cblxuICAvKipcbiAgICogQnVpbGRzIHRoZSBzdGF0ZWxlc3MgcnVsZSBncm91cCBsaXN0IG9iamVjdCBmcm9tIGN1cnJlbnQgc3RhdGVcbiAgICogdXNlcyB0aGlzLmJ1aWxkUnVsZUdyb3VwUmVmZXJlbmNlc1xuICAgKi9cbiAgcHJpdmF0ZSBidWlsZFN0YXRlbGVzc1J1bGVHcm91cFJlZmVyZW5jZXMoKTpDZm5GaXJld2FsbFBvbGljeS5TdGF0ZWxlc3NSdWxlR3JvdXBSZWZlcmVuY2VQcm9wZXJ0eVtdIHtcbiAgICBsZXQgcnVsZUdyb3VwUmVmZXJlbmNlczpDZm5GaXJld2FsbFBvbGljeS5TdGF0ZWxlc3NSdWxlR3JvdXBSZWZlcmVuY2VQcm9wZXJ0eVtdID0gW107XG4gICAgbGV0IHJ1bGVHcm91cDpTdGF0ZWxlc3NSdWxlR3JvdXBMaXN0O1xuICAgIGZvciAocnVsZUdyb3VwIG9mIHRoaXMuc3RhdGVsZXNzUnVsZUdyb3Vwcykge1xuICAgICAgcnVsZUdyb3VwUmVmZXJlbmNlcy5wdXNoKHtcbiAgICAgICAgcHJpb3JpdHk6IHJ1bGVHcm91cC5wcmlvcml0eSxcbiAgICAgICAgcmVzb3VyY2VBcm46IHJ1bGVHcm91cC5ydWxlR3JvdXAucnVsZUdyb3VwQXJuLFxuICAgICAgfSk7XG4gICAgfVxuICAgIHJldHVybiBydWxlR3JvdXBSZWZlcmVuY2VzO1xuICB9XG5cbiAgLyoqXG4gICAqIEJ1aWxkcyB0aGUgc3RhdGVmdWwgcnVsZSBncm91cCBsaXN0IG9iamVjdCBmcm9tIGN1cnJlbnQgc3RhdGVcbiAgICogdXNlcyB0aGlzLmJ1aWxkUnVsZUdyb3VwUmVmZXJlbmNlc1xuICAgKi9cbiAgcHJpdmF0ZSBidWlsZFN0YXRlZnVsUnVsZUdyb3VwUmVmZXJlbmNlcygpOkNmbkZpcmV3YWxsUG9saWN5LlN0YXRlZnVsUnVsZUdyb3VwUmVmZXJlbmNlUHJvcGVydHlbXSB7XG4gICAgbGV0IHJ1bGVHcm91cFJlZmVyZW5jZXM6Q2ZuRmlyZXdhbGxQb2xpY3kuU3RhdGVmdWxSdWxlR3JvdXBSZWZlcmVuY2VQcm9wZXJ0eVtdID0gW107XG4gICAgbGV0IHJ1bGVHcm91cDpTdGF0ZWZ1bFJ1bGVHcm91cExpc3Q7XG4gICAgZm9yIChydWxlR3JvdXAgb2YgdGhpcy5zdGF0ZWZ1bFJ1bGVHcm91cHMpIHtcbiAgICAgIGlmIChydWxlR3JvdXAucHJpb3JpdHkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBydWxlR3JvdXBSZWZlcmVuY2VzLnB1c2goe1xuICAgICAgICAgIHByaW9yaXR5OiBydWxlR3JvdXAucHJpb3JpdHksXG4gICAgICAgICAgcmVzb3VyY2VBcm46IHJ1bGVHcm91cC5ydWxlR3JvdXAucnVsZUdyb3VwQXJuLFxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJ1bGVHcm91cFJlZmVyZW5jZXMucHVzaCh7XG4gICAgICAgICAgcmVzb3VyY2VBcm46IHJ1bGVHcm91cC5ydWxlR3JvdXAucnVsZUdyb3VwQXJuLFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHJ1bGVHcm91cFJlZmVyZW5jZXM7XG4gIH1cblxuICAvKipcbiAgICogQ29udmVydHMgYSBTdGF0ZWZ1bChsZXNzKVJ1bGVHcm91cExpc3QgdG8gYSBTdGF0ZWZ1bChsZXNzKVJ1bGVHcm91cFJlZmVyZW5jZVByb3BlcnR5XG4gICAqL1xuICAvKnByaXZhdGUgYnVpbGRSdWxlR3JvdXBSZWZlcmVuY2VzKHJ1bGVHcm91cHM6KFN0YXRlZnVsUnVsZUdyb3VwTGlzdHxTdGF0ZWxlc3NSdWxlR3JvdXBMaXN0KVtdKSB7XG4gICAgbGV0IHJ1bGVHcm91cFJlZmVyZW5jZXM6Q2ZuRmlyZXdhbGxQb2xpY3kuU3RhdGVsZXNzUnVsZUdyb3VwUmVmZXJlbmNlUHJvcGVydHlbXXxDZm5GaXJld2FsbFBvbGljeS5TdGF0ZWZ1bFJ1bGVHcm91cFJlZmVyZW5jZVByb3BlcnR5ID0gW107XG4gICAgbGV0IHJ1bGVHcm91cDpTdGF0ZWZ1bFJ1bGVHcm91cExpc3R8U3RhdGVsZXNzUnVsZUdyb3VwTGlzdDtcbiAgICBmb3IgKHJ1bGVHcm91cCBvZiBydWxlR3JvdXBzKSB7XG4gICAgICBydWxlR3JvdXBSZWZlcmVuY2VzLnB1c2goe1xuICAgICAgICBwcmlvcml0eTogcnVsZUdyb3VwLnByaW9yaXR5LFxuICAgICAgICByZXNvdXJjZUFybjogcnVsZUdyb3VwLnJ1bGVHcm91cC5ydWxlR3JvdXBBcm4sXG4gICAgICB9KTtcbiAgICB9XG4gICAgcmV0dXJuIHJ1bGVHcm91cFJlZmVyZW5jZXM7XG4gIH0qL1xuXG4gIC8qKlxuICAgKiBUbyB2YWxpZGF0ZSBhIHNldCBvZiBydWxlIGdyb3VwcyB0byBlbnN1cmUgdGhleSBoYXZlIHVucWl1ZSBwcmlvcml0aWVzXG4gICAqL1xuICBwcml2YXRlIHZhbGlkYXRlVW5pcXVlUHJpb3JpdHkocnVsZUdyb3VwczphbnkpOmJvb2xlYW4ge1xuICAgIGxldCBwcmlvcml0aWVzOihudW1iZXJ8dW5kZWZpbmVkKVtdID0gW107XG4gICAgbGV0IHJ1bGVHcm91cDpTdGF0ZWZ1bFJ1bGVHcm91cExpc3Q7XG4gICAgZm9yIChydWxlR3JvdXAgb2YgcnVsZUdyb3Vwcykge1xuICAgICAgLy8gcHJpb3JpdGllcyBhcmUgb25seSByZXF1aXJlZCB3aGVuIHVzaW5nIHN0cmljdCBvcmRlciBldmF1bGF0aW9uLlxuICAgICAgLy8gRG9uJ3QgY2hlY2sgdW5kZWZpbmVkIHByaW9yaXRlcywgYXMgdGhlIHByaW9yaXR5IGNhbiBiZVxuICAgICAgLy8gZGV0ZXJtaW5lZCBpbXBsaWNpdGx5LlxuICAgICAgaWYgKHJ1bGVHcm91cC5wcmlvcml0eSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGlmIChwcmlvcml0aWVzLmluY2x1ZGVzKHJ1bGVHcm91cC5wcmlvcml0eSkpIHtcbiAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgcHJpb3JpdGllcy5wdXNoKHJ1bGVHcm91cC5wcmlvcml0eSk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xuICB9XG5cbiAgLyoqXG4gICAqIFZhbGlkYXRlcyB0aGF0IG9ubHkgb25lIG9jY3VyYW5jZSBvZiB0aGUgZW51bWVyYXRpb24gaXMgZm91bmQgaW4gdGhlIHZhbHVlcy5cbiAgICogVGhpcyBpcyBmb3IgdmVyaWZ5aW5nIG9ubHkgb25lIHN0YW5kYXJkIGRlZmF1bHQgYWN0aW9uIGlzIHVzZWQgaW4gYSBsaXN0LlxuICAgKi9cbiAgcHJpdmF0ZSB2YWxpZGF0ZU9ubHlPbmUoZW51bWVyYXRpb246YW55LCB2YWx1ZXM6c3RyaW5nW10pOmJvb2xlYW4ge1xuICAgIGxldCBvbmVGb3VuZDpib29sZWFuID0gZmFsc2U7XG4gICAgbGV0IHZhbHVlOnN0cmluZztcbiAgICBmb3IgKHZhbHVlIG9mIHZhbHVlcykge1xuICAgICAgaWYgKE9iamVjdC52YWx1ZXM8c3RyaW5nPihlbnVtZXJhdGlvbikuaW5jbHVkZXModmFsdWUpKSB7XG4gICAgICAgIGlmIChvbmVGb3VuZCkge1xuICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBvbmVGb3VuZCA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xuICB9XG59Il19