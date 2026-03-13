import re
import ipaddress
from collections import defaultdict
from pathlib import Path


def is_real_ip(ip_str):
    try:
        if '/' in ip_str:
            ip = ipaddress.ip_network(ip_str, strict=False)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
        else:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def parse_rule_line(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None, None, None

    pattern = r'set\s+rulebase\s+security\s+rules\s+"([^"]+)"\s+(.+)'
    match = re.match(pattern, line)

    if match:
        rule_name = match.group(1)
        rest_of_line = match.group(2).strip()

        attributes = ['from', 'to', 'source', 'destination', 'source-user', 'application', 'service', 'action', 'log-start', 'log-end', 'description', 'disabled', 'tag']
        attr_pattern = r'\b(' + '|'.join(attributes) + r')\b'
        parts = re.split(attr_pattern, rest_of_line)

        results = []
        i = 1
        while i < len(parts):
            if i + 1 < len(parts):
                attr = parts[i].strip()
                value_part = parts[i + 1].strip()

                if value_part.startswith('['):
                    bracket_end = value_part.find(']')
                    if bracket_end != -1:
                        values = value_part[1:bracket_end].strip().split()
                    else:
                        values = [value_part]
                else:
                    values = [value_part.split()[0]] if value_part else []

                results.append((rule_name, attr, values))
                i += 2
            else:
                i += 1

        return results if results else [(rule_name, None, None)]

    return None, None, None


def parse_rules_from_file(filepath):
    rules = defaultdict(lambda: {
        'from': [], 'to': [], 'source': [], 'destination': [],
        'source-user': [], 'application': [], 'service': [],
        'action': None, 'description': None, 'log-start': None,
        'log-end': None, 'disabled': None, 'tag': []
    })

    line_count = 0

    with open(filepath, 'r', encoding='utf-8', buffering=8192) as f:
        for line in f:
            line_count += 1

            if line_count % 100000 == 0:
                print(f"      Processing line {line_count:,}...")

            result = parse_rule_line(line)

            if result and isinstance(result, list):
                for rule_name, attribute, values in result:
                    if rule_name and attribute and values:
                        if attribute in ['from', 'to', 'source', 'destination', 'source-user', 'application', 'service', 'tag']:
                            rules[rule_name][attribute].extend(values)
                        elif attribute in ['action', 'description', 'log-start', 'log-end', 'disabled']:
                            rules[rule_name][attribute] = values[0] if values else None
            elif result:
                rule_name, attribute, values = result
                if rule_name and attribute and values:
                    if attribute in ['from', 'to', 'source', 'destination', 'source-user', 'application', 'service', 'tag']:
                        rules[rule_name][attribute].extend(values)
                    elif attribute in ['action', 'description', 'log-start', 'log-end', 'disabled']:
                        rules[rule_name][attribute] = values[0] if values else None

    print(f"      Total lines processed: {line_count:,}")
    return dict(rules)


def filter_real_ips_from_sources(sources):
    filtered = []
    real_ips_found = []

    for src in sources:
        if is_real_ip(src):
            real_ips_found.append(src)
        else:
            filtered.append(src)

    return filtered, real_ips_found


def create_rule_signature(rule):
    from_zones = tuple(sorted(set(rule['from']))) if rule['from'] else ('any',)
    to_zones = tuple(sorted(set(rule['to']))) if rule['to'] else ('any',)
    action = rule['action'] or 'allow'
    apps = tuple(sorted(set(rule['application']))) if rule['application'] else ('any',)
    services = tuple(sorted(set(rule['service']))) if rule['service'] else ('application-default',)

    return (from_zones, to_zones, action, apps, services)


def group_rules_by_signature(rules):
    signature_groups = defaultdict(list)

    for rule_name, rule_data in rules.items():
        if rule_data.get('disabled') == 'yes':
            continue
        signature = create_rule_signature(rule_data)
        signature_groups[signature].append(rule_name)

    return signature_groups


def merge_rules(rules, rule_names, merged_rule_name):
    merged = {
        'from': set(), 'to': set(), 'source': set(), 'destination': set(),
        'source-user': set(), 'application': set(), 'service': set(),
        'action': None, 'description': None, 'log-end': 'yes', 'original_rules': []
    }

    all_real_source_ips = []

    for rule_name in rule_names:
        rule = rules[rule_name]
        merged['original_rules'].append(rule_name)

        merged['from'].update(rule['from'] if rule['from'] else ['any'])
        merged['to'].update(rule['to'] if rule['to'] else ['any'])

        filtered_sources, real_ips = filter_real_ips_from_sources(rule['source'])
        merged['source'].update(filtered_sources)
        all_real_source_ips.extend(real_ips)

        merged['destination'].update(rule['destination'] if rule['destination'] else ['any'])
        merged['source-user'].update(rule['source-user'] if rule['source-user'] else ['any'])
        merged['application'].update(rule['application'] if rule['application'] else ['any'])
        merged['service'].update(rule['service'] if rule['service'] else ['application-default'])

        if merged['action'] is None:
            merged['action'] = rule['action'] or 'allow'

    merged['description'] = f"Merged from {len(rule_names)} rules: {', '.join(rule_names[:5])}"
    if len(rule_names) > 5:
        merged['description'] += f" ... and {len(rule_names) - 5} more"

    for key in ['from', 'to', 'source', 'destination', 'source-user', 'application', 'service']:
        merged[key] = sorted(merged[key])

    return merged, all_real_source_ips


def generate_palo_alto_config(merged_rules, output_file):
    with open(output_file, 'w', encoding='utf-8', buffering=8192) as f:
        rule_count = 0
        for rule_name, rule_data in sorted(merged_rules.items()):
            rule_count += 1

            rule_parts = [f'set rulebase security rules "{rule_name}"']

            from_zones = [z for z in rule_data['from'] if z.lower() != 'any']
            to_zones = [z for z in rule_data['to'] if z.lower() != 'any']

            if from_zones:
                rule_parts.append(f'from {" ".join(from_zones)}')
            if to_zones:
                rule_parts.append(f'to {" ".join(to_zones)}')

            sources = [s for s in rule_data['source'] if s.lower() != 'any']
            if sources:
                rule_parts.append(f'source [ {" ".join(sources)} ]')

            destinations = [d for d in rule_data['destination'] if d.lower() != 'any']
            if destinations:
                rule_parts.append(f'destination [ {" ".join(destinations)} ]')

            users = [u for u in rule_data['source-user'] if u.lower() != 'any']
            if users:
                rule_parts.append(f'source-user [ {" ".join(users)} ]')

            apps = [a for a in rule_data['application'] if a.lower() != 'any']
            if apps:
                rule_parts.append(f'application [ {" ".join(apps)} ]')

            services = [s for s in rule_data['service'] if s.lower() not in ['any', 'application-default']]
            if services:
                rule_parts.append(f'service [ {" ".join(services)} ]')

            rule_parts.append(f'action {rule_data["action"]}')
            rule_parts.append(f'log-end {rule_data["log-end"]}')

            f.write(' '.join(rule_parts) + '\n\n')


def merge_paloalto_rules(input_file, target_rule_count=30):
    print(f"\n[1/6] Parsing rules from {input_file}...")
    rules = parse_rules_from_file(input_file)
    print(f"      Found {len(rules):,} unique rules")

    print("[2/6] Grouping rules by similarity...")
    signature_groups = group_rules_by_signature(rules)
    print(f"      Created {len(signature_groups):,} signature groups")

    sorted_groups = sorted(signature_groups.items(), key=lambda x: len(x[1]), reverse=True)

    print(f"[3/6] Merging rules into {target_rule_count} groups...")

    merged_rules = {}
    all_excluded_ips = []
    groups_to_process = min(target_rule_count, len(sorted_groups))

    for idx, (signature, rule_names) in enumerate(sorted_groups[:groups_to_process], 1):
        merged_rule_name = f"Merged-Rule-{idx}"
        merged_rule, excluded_ips = merge_rules(rules, rule_names, merged_rule_name)
        merged_rules[merged_rule_name] = merged_rule
        all_excluded_ips.extend(excluded_ips)
        print(f"      {merged_rule_name}: Merged {len(rule_names):,} rules")

    remaining_groups = sorted_groups[groups_to_process:]
    if remaining_groups and len(merged_rules) < target_rule_count:
        remaining_by_action = defaultdict(list)
        for signature, rule_names in remaining_groups:
            action = signature[2]
            remaining_by_action[action].extend(rule_names)

        for action, rule_names in remaining_by_action.items():
            if len(merged_rules) >= target_rule_count:
                break
            merged_rule_name = f"Merged-Rule-{len(merged_rules) + 1}-{action.upper()}"
            merged_rule, excluded_ips = merge_rules(rules, rule_names, merged_rule_name)
            merged_rules[merged_rule_name] = merged_rule
            all_excluded_ips.extend(excluded_ips)

    print(f"[4/6] Total merged rules: {len(merged_rules):,}")
    print(f"[5/6] Real source IPs excluded: {len(set(all_excluded_ips)):,}")
    print("[6/6] Generating output files...")

    input_path = Path(input_file)
    output_config = input_path.parent / f"{input_path.stem}_merged_config.txt"
    output_excluded_ips = input_path.parent / f"{input_path.stem}_excluded_real_ips.txt"
    output_mapping = input_path.parent / f"{input_path.stem}_merge_mapping.txt"

    generate_palo_alto_config(merged_rules, output_config)

    with open(output_excluded_ips, 'w', encoding='utf-8', buffering=8192) as f:
        f.write("Real (Public) Source IPs Excluded from Merged Rules\n")
        f.write("=" * 70 + "\n\n")
        for ip in sorted(set(all_excluded_ips)):
            f.write(f"{ip}\n")

    with open(output_mapping, 'w', encoding='utf-8', buffering=8192) as f:
        f.write("Mapping: Original Rules -> Merged Rules\n")
        f.write("=" * 70 + "\n\n")
        for merged_name, merged_data in sorted(merged_rules.items()):
            f.write(f"\n{merged_name}:\n")
            f.write(f"  From Zones: {', '.join(merged_data['from'])}\n")
            f.write(f"  To Zones: {', '.join(merged_data['to'])}\n")
            f.write(f"  Action: {merged_data['action']}\n")
            f.write(f"  Original Rules ({len(merged_data['original_rules']):,}):\n")
            for orig in merged_data['original_rules']:
                f.write(f"    - {orig}\n")

    print(f"\nOriginal rules processed:  {len(rules):,}")
    print(f"Merged rules created:      {len(merged_rules):,}")
    print(f"Real source IPs excluded:  {len(set(all_excluded_ips)):,}")
    print(f"\nOutput files:")
    print(f"  1. {output_config}")
    print(f"  2. {output_excluded_ips}")
    print(f"  3. {output_mapping}")

    return merged_rules, all_excluded_ips


def main():
    input_file = input("Enter path to your Palo Alto rules file: ").strip()

    if not Path(input_file).exists():
        print(f"Error: File '{input_file}' not found.")
        return

    try:
        target_count = int(input("Enter target number of merged rules (default 30): ").strip() or "30")
    except ValueError:
        target_count = 30

    try:
        merge_paloalto_rules(input_file, target_count)
        print("\nMerge completed successfully!")
    except Exception as e:
        print(f"\nError during merge: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()