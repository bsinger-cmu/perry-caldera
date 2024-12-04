import inspect

import plugins.deception.app.strategies.equifax_baseline as equifax
import plugins.deception.app.strategies.networkDFS as networkDFS
import plugins.deception.app.strategies.targeted as targeted
import plugins.deception.app.strategies.persistentDFS as persistentDFS
import plugins.deception.app.strategies.darkside as darkside

import plugins.deception.app.actions.LowLevelAction as LowLevelAction
import plugins.deception.app.actions.LowLevel as LowLevel
from plugins.deception.app.actions.LowLevelAction import LowLevelAction

# Knowledge modules
from plugins.deception.app.services import (
    EnvironmentStateService,
    AttackGraphService,
    LowLevelActionOrchestrator,
    HighLevelActionOrchestrator,
)

from plugins.deception.app.helpers.ability_helpers import run_ability

from plugins.deception.app.models.network import Network
from plugins.deception.app.models.network import Subnet
from plugins.deception.app.models.network import Host
from plugins.deception.app.models.network import SSHCredential


from plugins.deception.app.actions.HighLevel import (
    Scan,
    FindInformationOnAHost,
    LateralMoveToHost,
    ExfiltrateData,
    AttackPathLateralMove,
)

from rich import print


def count_saved_lines(lines, func_line_map={}):
    saved_lines = 0
    func_calls = {}
    for key, _ in func_line_map.items():
        func_calls[key] = 0

    for line in lines:
        for key, value in func_line_map.items():
            if (key) in line:
                saved_lines += value
                func_calls[key] += 1
                break

    return saved_lines, func_calls


def count_lines_in_high_level_action(
    high_level_action, low_level_actions, env_funcs={}, ag_funcs={}
):
    low_level_action_planner_map = {}
    low_level_obs_map = {}
    for key, value in low_level_actions.items():
        low_level_action_planner_map[key] = value[1]
        low_level_obs_map[key] = value[2]

    perry_lines = get_function_semantic_lines(high_level_action)
    action_planner_lines = count_saved_lines(perry_lines, low_level_action_planner_map)
    obs_lines = count_saved_lines(perry_lines, low_level_obs_map)
    env_lines = count_saved_lines(perry_lines, env_funcs)
    ag_lines = count_saved_lines(perry_lines, ag_funcs)

    total_lines = (
        action_planner_lines[0]
        + env_lines[0]
        + ag_lines[0]
        + len(perry_lines)
        + obs_lines[0]
    )

    return total_lines, action_planner_lines[0], env_lines[0], ag_lines[0], obs_lines[0]


def count_lines_in_low_level_action(low_level_action):
    # Lines required to create and remove facts
    add_fact_lines = len(
        get_function_semantic_lines(LowLevelActionOrchestrator.add_fact)
    )
    remove_fact_lines = len(
        get_function_semantic_lines(LowLevelActionOrchestrator.remove_fact)
    )
    # Lines required to run action
    run_action_lines = len(
        get_function_semantic_lines(LowLevelActionOrchestrator.run_action)
    )
    # run_action_lines += len(get_function_semantic_lines(run_ability))

    # __init__ lines
    init_lines = len(get_function_semantic_lines(low_level_action.__init__))
    init_lines += len(get_function_semantic_lines(LowLevelAction.__init__))

    # Get result counter
    obs_lines = len(get_function_semantic_lines(low_level_action.get_result))
    action_planner_lines = (
        add_fact_lines + remove_fact_lines + run_action_lines + init_lines
    )

    total = action_planner_lines + obs_lines

    return total, action_planner_lines, obs_lines


def get_function_semantic_lines(functions):
    if not isinstance(functions, list):
        functions = [functions]

    semantic_lines = []
    for func in functions:
        lines = inspect.getsourcelines(func)
        semantic_lines += count_semantic_lines(lines[0])

    return semantic_lines


def count_semantic_lines(lines):
    semantic_lines = []
    for line in lines:
        if line.strip().startswith("#"):
            continue
        if "log_event" in line.strip():
            continue
        if line.strip() == "":
            continue
        if line.strip() == "\n":
            continue

        semantic_lines.append(line)
    return semantic_lines


def num_semantic_lines_in_func(function):
    lines = get_function_semantic_lines(function)
    return len(count_semantic_lines(lines))


def count_saved_knowledge_lines(lines, knowledge_actions):
    total_saved_lines = 0

    high_level_action_calls = {}
    for key, _ in knowledge_actions.items():
        high_level_action_calls[key] = 0

    for line in lines:
        for key, value in knowledge_actions.items():
            if key in line:
                total_saved_lines += value
                high_level_action_calls[key] += 1
                break
    return total_saved_lines


def print_result(
    strategy_name, lines, high_level_actions={}, ag_funcs={}, env_funcs={}
):
    perry_lines = len(lines)

    # Build a map of function names to the number of lines in the function
    high_level_line_map = {}
    for key, value in high_level_actions.items():
        high_level_line_map[key] = value[0]

    saved_action_lines, high_level_func_calls = count_saved_lines(
        lines, high_level_line_map
    )

    action_planner_saved_lines = 0
    obs_saved_lines = 0
    ag_saved_lines, _ = count_saved_lines(lines, ag_funcs)
    env_saved_lines, _ = count_saved_lines(lines, env_funcs)
    # Add from high-level actions
    for key, value in high_level_func_calls.items():
        high_level_action_lines = high_level_actions[key]

        action_planner_saved_lines += high_level_action_lines[1] * value
        env_saved_lines += high_level_action_lines[2] * value
        ag_saved_lines += high_level_action_lines[3] * value
        obs_saved_lines += high_level_action_lines[4] * value

    caldera_lines = perry_lines + saved_action_lines + ag_saved_lines + env_saved_lines

    print(f"### {strategy_name} ###")
    print(f"Lines in Perry: {perry_lines}")
    print(f"Lines in Caldera: {caldera_lines}")
    print(f"Saved action lines: {saved_action_lines}")
    print(f"Saved env lines: {env_saved_lines}")
    print(f"Saved ag lines: {ag_saved_lines}")
    print(f"Saved obs lines: {obs_saved_lines}")


def count_parse_event_lines(lines):
    parse_event_lines = 0
    for line in lines:
        if "parse_events" in line:
            parse_event_lines += 1
    return parse_event_lines


def count_saved_from_symbolic(lines):
    num_parsed_events = count_parse_event_lines(lines)

    parse_event_lines = get_function_semantic_lines(
        [EnvironmentStateService.parse_events]
    )

    parse_events_lines = len(count_semantic_lines(parse_event_lines))

    return num_parsed_events * parse_events_lines


if __name__ == "__main__":
    low_level_actions = {
        "FindSSHConfig": count_lines_in_low_level_action(LowLevel.FindSSHConfig),
        "ListFilesInDirectory": count_lines_in_low_level_action(
            LowLevel.ListFilesInDirectory
        ),
        "ReadFile": count_lines_in_low_level_action(LowLevel.ReadFile),
        "SCPFile": count_lines_in_low_level_action(LowLevel.SCPFile),
        "wgetFile": count_lines_in_low_level_action(LowLevel.wgetFile),
        "MD5SumAttackerData": count_lines_in_low_level_action(
            LowLevel.MD5SumAttackerData
        ),
        "ExploitStruts": count_lines_in_low_level_action(LowLevel.ExploitStruts),
        "SSHLateralMove": count_lines_in_low_level_action(LowLevel.SSHLateralMove),
        "ScanHost": count_lines_in_low_level_action(LowLevel.ScanHost),
        "ScanNetwork": count_lines_in_low_level_action(LowLevel.ScanNetwork),
        "NCLateralMove": count_lines_in_low_level_action(LowLevel.NCLateralMove),
        "CopyFile": count_lines_in_low_level_action(LowLevel.CopyFile),
        "RunBashCommand": count_lines_in_low_level_action(LowLevel.RunBashCommand),
    }

    env_state_functions = {
        "update_host_agents": num_semantic_lines_in_func(
            EnvironmentStateService.update_host_agents
        ),
        "add_infected_host": num_semantic_lines_in_func(
            EnvironmentStateService.add_infected_host
        ),
        "get_hosts_with_agents": num_semantic_lines_in_func(
            EnvironmentStateService.get_hosts_with_agents
        ),
        "add_host": num_semantic_lines_in_func(Network.add_host),
        "find_host_by_hostname": num_semantic_lines_in_func(
            Network.find_host_by_hostname
        ),
        "find_host_by_ip": num_semantic_lines_in_func(Network.find_host_by_ip),
        "find_agent_for_host": num_semantic_lines_in_func(Network.find_agent_for_host),
        "find_host_by_agent": num_semantic_lines_in_func(Network.find_host_by_agent),
        "get_all_hosts": num_semantic_lines_in_func(Network.get_all_hosts),
        "get_non_infected_subnets": num_semantic_lines_in_func(
            Network.get_non_infected_subnets
        ),
        "find_subnet_by_ip_mask": num_semantic_lines_in_func(
            Network.find_subnet_by_ip_mask
        ),
    }

    attack_graph_functions = {
        "already_executed_attack_path": num_semantic_lines_in_func(
            AttackGraphService.already_executed_attack_path
        ),
        "executed_attack_path": num_semantic_lines_in_func(
            AttackGraphService.executed_attack_path
        ),
        "find_hosts_with_credentials_to_host": num_semantic_lines_in_func(
            AttackGraphService.find_hosts_with_credentials_to_host
        ),
        "get_possible_attack_paths": num_semantic_lines_in_func(
            AttackGraphService.get_possible_attack_paths
        ),
        "get_attack_paths_to_target": num_semantic_lines_in_func(
            AttackGraphService.get_attack_paths_to_target
        ),
        "get_possible_targets_from_host": num_semantic_lines_in_func(
            AttackGraphService.get_possible_targets_from_host
        ),
    }

    high_level_actions = {
        "Scan(": count_lines_in_high_level_action(
            Scan.run,
            low_level_actions,
            env_state_functions,
            attack_graph_functions,
        ),
        "DiscoverHostInformation(": count_lines_in_high_level_action(
            FindInformationOnAHost.run,
            low_level_actions,
            env_state_functions,
            attack_graph_functions,
        ),
        "LateralMoveToHost(": count_lines_in_high_level_action(
            LateralMoveToHost.run,
            low_level_actions,
            env_state_functions,
            attack_graph_functions,
        ),
        "ExfiltrateData(": count_lines_in_high_level_action(
            ExfiltrateData.run,
            low_level_actions,
            env_state_functions,
            attack_graph_functions,
        ),
        "AttackPathLateralMove(": count_lines_in_high_level_action(
            AttackPathLateralMove.run,
            low_level_actions,
            env_state_functions,
            attack_graph_functions,
        ),
    }

    print("### Low Level Actions ###")
    print(low_level_actions)

    print("### High Level Actions ###")
    print(high_level_actions)

    parse_events_functions = [
        EnvironmentStateService.parse_events,
        EnvironmentStateService.handle_CrendentialFound,
        EnvironmentStateService.handle_CriticalDataFound,
        EnvironmentStateService.handle_HostsDiscovered,
        EnvironmentStateService.handle_InfectedNewHost,
        EnvironmentStateService.handle_ServicesDiscoveredOnHost,
    ]

    equifax_functions = [
        equifax.LogicalPlanner.main,
        equifax.LogicalPlanner.initial_access,
        equifax.LogicalPlanner.cred_exfiltrate,
    ]

    networkDFS_functions = [
        networkDFS.LogicalPlanner.main,
        networkDFS.LogicalPlanner.initial_access,
        networkDFS.LogicalPlanner.random_spread,
    ]

    targeted_functions = [
        targeted.LogicalPlanner.main,
        targeted.LogicalPlanner.initial_access,
        targeted.LogicalPlanner.random_spread,
        targeted.LogicalPlanner.choose_attack_path,
    ]

    persistentDFS_functions = [
        persistentDFS.LogicalPlanner.main,
        persistentDFS.LogicalPlanner.initial_access,
        persistentDFS.LogicalPlanner.explore_network,
    ]

    darkside_functions = [
        darkside.LogicalPlanner.main,
        darkside.LogicalPlanner.initial_access,
        darkside.LogicalPlanner.complete_mission,
        darkside.LogicalPlanner.infect_network,
    ]

    equifax_lines = get_function_semantic_lines(equifax_functions)
    networkDFS_lines = get_function_semantic_lines(networkDFS_functions)
    ICSTargeted_lines = get_function_semantic_lines(targeted_functions)
    persistentDFS_lines = get_function_semantic_lines(persistentDFS_functions)
    darkside_lines = get_function_semantic_lines(darkside_functions)

    print_result(
        "Equifax",
        equifax_lines,
        high_level_actions,
        env_funcs=env_state_functions,
        ag_funcs=attack_graph_functions,
    )
    print_result(
        "networkDFS",
        networkDFS_lines,
        high_level_actions,
        env_funcs=env_state_functions,
        ag_funcs=attack_graph_functions,
    )
    print_result(
        "ICSTargeted",
        ICSTargeted_lines,
        high_level_actions,
        env_funcs=env_state_functions,
        ag_funcs=attack_graph_functions,
    )
    print_result(
        "PersistentDFS",
        persistentDFS_lines,
        high_level_actions,
        env_funcs=env_state_functions,
        ag_funcs=attack_graph_functions,
    )
    print_result(
        "Darkside",
        darkside_lines,
        high_level_actions,
        env_funcs=env_state_functions,
        ag_funcs=attack_graph_functions,
    )

    print("### LOC of env state serveice ###")
    network_lines = get_function_semantic_lines(Network)
    subnet_lines = get_function_semantic_lines(Subnet)
    host_lines = get_function_semantic_lines(Host)
    credential_lines = get_function_semantic_lines(SSHCredential)

    static_lines = (
        len(network_lines) + len(subnet_lines) + len(host_lines) + len(credential_lines)
    )
