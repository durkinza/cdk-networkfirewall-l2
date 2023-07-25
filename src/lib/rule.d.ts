import { StatefulStandardAction, StatelessStandardAction } from './actions';
import { CfnRuleGroup } from 'aws-cdk-lib/aws-networkfirewall';
/**
 * The interface that represents the values of a StatelessRule
 */
export interface IStatelessRule {
}
/**
 * The base class of Stateless Rules
 */
declare abstract class StatelessRuleBase implements IStatelessRule {
}
/**
 * Properties for defining a stateless rule
 */
export interface StatelessRuleProps {
    /**
     * Rule Actions
     *
     * The actions to take on a packet that matches one of the stateless rule definition's match attributes.
     */
    readonly actions: (StatelessStandardAction | string)[];
    /**
     * The destination port to inspect for.
     * You can specify an individual port, for example 1994 and you can specify a port range, for example 1990:1994.
     * To match with any port, specify ANY.
     *
     * @default - ANY
     */
    readonly destinationPorts?: CfnRuleGroup.PortRangeProperty[];
    /**
     * Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.
     *
     * @default - ANY
     */
    readonly destinations?: string[];
    /**
     * The protocols to inspect for, specified using each protocol's assigned internet protocol number (IANA).
     *
     * @default - ANY
     */
    readonly protocols?: number[];
    /**
     * The source ports to inspect for.
     *
     * @default - ANY
     */
    readonly sourcePorts?: CfnRuleGroup.PortRangeProperty[];
    /**
     * Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.
     *
     * @default - ANY
     */
    readonly sources?: string[];
    /**
     * TCP flags and masks to inspect packets for.
     *
     * @default - undefined
     */
    readonly tcpFlags?: CfnRuleGroup.TCPFlagFieldProperty[];
}
/**
 * Defines a Network Firewall Stateless Rule
 */
export declare class StatelessRule extends StatelessRuleBase {
    private readonly destinations;
    private readonly destinationPorts;
    private readonly sources;
    private readonly sourcePorts;
    private readonly protocols;
    /**
     * The L1 Stateless Rule Property
     * @attribute
     */
    resource: CfnRuleGroup.RuleDefinitionProperty;
    constructor(props: StatelessRuleProps);
    /**
     * Calculate the address capacity requirements by number of address ranges.
     */
    private calculateAddressCapacity;
    /**
     * Calculate Rule Capacity Reqirements.
     * https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-group-managing.html#nwfw-rule-group-capacity
     */
    calculateCapacity(): number;
}
/**
 * The direction of traffic flow to inspect.
 */
export declare enum Stateful5TupleDirection {
    /**
     * Inspection matches bidirectional traffic, both from the source to the destination and from the destination to the source.
     */
    ANY = "ANY",
    /**
     * Inspection only matches traffic going from the source to the destination.
     */
    FORWARD = "FORWARD"
}
/**
 * The interface that represents the shared values of the StatefulRules
 */
export interface IStatefulRule {
}
/**
 * The properties for defining a generic Stateful Rule
 */
export interface StatefulRuleBaseProps {
}
/**
 * The shared base class of stateful rules.
 */
export declare abstract class StatefulRuleBase implements IStatefulRule {
}
/**
 * Properties for defining a 5 Tuple rule
 */
export interface Stateful5TupleRuleProps extends StatefulRuleBaseProps {
    /**
     * The action to perform when a rule is matched.
     */
    readonly action: StatefulStandardAction | string;
    /**
     * The destination port to inspect for.
     * You can specify an individual port, for example 1994 and you can specify a port range, for example 1990:1994 .
     * To match with any port, specify ANY
     *
     * @default - ANY
     */
    readonly destinationPort?: string;
    /**
     * Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.
     *
     * @default = ANY
     */
    readonly destination?: string;
    /**
     * The protocol to inspect for.
     * To specify all, you can use IP , because all traffic on AWS and on the internet is IP.
     *
     * @default - IP
     */
    readonly protocol?: string;
    /**
     * The source IP address or address range to inspect for, in CIDR notation.
     * To match with any address, specify ANY.
     *
     * @default - ANY
     */
    readonly sourcePort?: string;
    /**
     * Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.
     *
     * @default = ANY
     */
    readonly source?: string;
    /**
     * Additional settings for a stateful rule, provided as keywords and setttings.
     *
     * @default - undefined
     */
    readonly ruleOptions?: CfnRuleGroup.RuleOptionProperty[];
    /**
     * The direction of traffic flow to inspect.
     * If set to ANY, the inspection matches bidirectional traffic, both from the source to the destination and from the destination to the source.
     * If set to FORWARD , the inspection only matches traffic going from the source to the destination.
     *
     * @default - ANY
     */
    readonly direction?: Stateful5TupleDirection | string;
}
/**
 * Generates a Stateful Rule from a 5 Tuple
 */
export declare class Stateful5TupleRule extends StatefulRuleBase {
    /**
     * The L1 Stateful Rule Property
     * @attribute
     */
    resource: CfnRuleGroup.StatefulRuleProperty;
    constructor(props: Stateful5TupleRuleProps);
}
/**
 * The type of domain list to generate
 */
export declare enum StatefulDomainListType {
    /**
     * Deny domain(s) through
     */
    DENYLIST = "DENYLIST",
    /**
     * Allow domain(s) through
     */
    ALLOWLIST = "ALLOWLIST"
}
/**
 * The types of targets to inspect for.
 *  You can inspect HTTP or HTTPS protocols, or both.
 */
export declare enum StatefulDomainListTargetType {
    /**
     * Target HTTPS traffic
     * For HTTPS traffic, Network Firewall uses the Server Name Indication (SNI) extension in the TLS handshake to determine the hostname, or domain name, that the client is trying to connect to
     */
    TLS_SNI = "TLS_SNI",
    /**
     * Target HTTP traffic
     */
    HTTP_HOST = "HTTP_HOST"
}
/**
 * The properties for defining a Stateful Domain List Rule
 */
export interface StatefulDomainListRuleProps extends StatefulRuleBaseProps {
    /**
     * Whether you want to allow or deny access to the domains in your target list.
     */
    readonly type: StatefulDomainListType | string;
    /**
     * The domains that you want to inspect for in your traffic flows.
     */
    readonly targets: string[];
    /**
     * The types of targets to inspect for.
     */
    readonly targetTypes: (StatefulDomainListTargetType | string)[];
}
/**
 * Generates a Statful Rule from a Domain List
 */
export declare class StatefulDomainListRule extends StatefulRuleBase {
    /**
     * The L1 Stateful Rule Property
     * @attribute
     */
    resource: CfnRuleGroup.RulesSourceListProperty;
    constructor(props: StatefulDomainListRuleProps);
}
export {};
