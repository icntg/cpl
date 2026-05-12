#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pathlib import Path


def extract_namespace_structure(content):
    """Extract namespace structure from sys.hpp, handling NOT_NECESSARY macro."""
    content = re.sub(r'\s+using\s+namespace\s+[^;]*;', '', content)

    cpl_start = content.find('namespace cpl {')
    if cpl_start == -1:
        raise ValueError('Could not find cpl namespace')

    sys_start = content.find('namespace sys {', cpl_start)
    if sys_start == -1:
        raise ValueError('Could not find sys namespace')

    api_start = content.find('namespace api {', sys_start)
    if api_start == -1:
        raise ValueError('Could not find api namespace')

    api_start_pos = api_start + len('namespace api {')
    brace_count = 1
    pos = api_start_pos
    while pos < len(content) and brace_count > 0:
        if content[pos] == '{':
            brace_count += 1
        elif content[pos] == '}':
            brace_count -= 1
        pos += 1

    if brace_count != 0:
        raise ValueError('Could not find matching closing brace for cpl::sys::api namespace')

    api_content = content[api_start_pos:pos - 1]
    sub_namespaces = {}

    namespace_pos = 0
    while namespace_pos < len(api_content):
        namespace_match = re.search(r'namespace\s+(\w+)\s*{', api_content[namespace_pos:], re.DOTALL)
        if not namespace_match:
            break

        namespace_name = namespace_match.group(1)
        namespace_start = namespace_pos + namespace_match.end() - 1

        brace_count = 1
        pos = namespace_start + 1
        while pos < len(api_content) and brace_count > 0:
            if api_content[pos] == '{':
                brace_count += 1
            elif api_content[pos] == '}':
                brace_count -= 1
            pos += 1

        if brace_count != 0:
            namespace_pos = namespace_start + 1
            continue

        namespace_content = api_content[namespace_start + 1:pos - 1]
        sub_namespaces[namespace_name] = {
            'content': namespace_content,
            'dll_names': [],
            'functions': [],
            'necessary': True,
        }

        dll_match = re.search(
            r'const\s+std::?::?vector\s*<\s*std::?::?string\s*>\s+DLL_NAMES\s*=\s*{([^}]*)}',
            namespace_content,
        )
        if not dll_match:
            dll_match = re.search(
                r'const\s+vector\s*<\s*string\s*>\s+DLL_NAMES\s*=\s*{([^}]*)}',
                namespace_content,
            )

        if dll_match:
            line_start = namespace_content.rfind('\n', 0, dll_match.start()) + 1
            line_end = namespace_content.find('\n', dll_match.end())
            if line_end == -1:
                line_end = len(namespace_content)
            line_content = namespace_content[line_start:line_end]

            sub_namespaces[namespace_name]['necessary'] = 'NOT_NECESSARY' not in line_content
            sub_namespaces[namespace_name]['dll_names'] = re.findall(r'"([^"]*)"', dll_match.group(1))

        typedef_pos = 0
        while typedef_pos < len(namespace_content):
            typedef_match = re.search(r'\btypedef\b', namespace_content[typedef_pos:])
            if not typedef_match:
                break

            typedef_start = typedef_pos + typedef_match.start()
            semicolon_pos = namespace_content.find(';', typedef_start)
            if semicolon_pos == -1:
                typedef_pos = typedef_start + 1
                continue

            typedef_statement = namespace_content[typedef_start:semicolon_pos + 1]

            if re.search(r'\btypedef\s+(?:struct|union)\b', typedef_statement):
                typedef_pos = semicolon_pos + 1
                continue

            if 'WINAPI' not in typedef_statement:
                typedef_pos = semicolon_pos + 1
                continue

            func_name_match = re.search(r'\(\s*WINAPI\s*\*\s*(\w+)\s*\)', typedef_statement)
            if not func_name_match:
                typedef_pos = semicolon_pos + 1
                continue

            func_name = func_name_match.group(1)
            if func_name in ['WINAPI', 'NTSYSAPI', '__kernel_entry']:
                typedef_pos = semicolon_pos + 1
                continue

            line_start = namespace_content.rfind('\n', 0, typedef_start) + 1
            line_end = namespace_content.find('\n', typedef_start)
            if line_end == -1:
                line_end = len(namespace_content)

            line_content = namespace_content[line_start:typedef_start]
            line_without_comments = re.sub(r'/\*.*?\*/', '', line_content)
            line_without_comments = re.sub(r'//.*$', '', line_without_comments)
            line_before_typedef = line_without_comments.strip()

            has_not_necessary = False
            if line_before_typedef.endswith('NOT_NECESSARY'):
                before_not_necessary = line_before_typedef[:-len('NOT_NECESSARY')].strip()
                if not before_not_necessary:
                    has_not_necessary = True

            if not any(f['name'] == func_name for f in sub_namespaces[namespace_name]['functions']):
                sub_namespaces[namespace_name]['functions'].append({
                    'name': func_name,
                    'necessary': not has_not_necessary,
                })

            typedef_pos = semicolon_pos + 1

        namespace_pos = pos

    return sub_namespaces


def generate_api_header(sub_namespaces):
    """Generate api.hpp content with DynamicModule classes for each sub-namespace."""
    header = '''//// this file was generated by api_gen.py. please DO NOT edit this file directly.
#pragma once

#include "sys.hpp"

namespace cpl {
namespace sys {
namespace api {
'''

    for namespace_name, data in sub_namespaces.items():
        header += f'namespace {namespace_name} {{\n'
        header += '    class DynamicModule final : public api::DynamicModule {\n'
        header += '    public:\n'

        if not data['necessary']:
            header += '        explicit DynamicModule() : api::DynamicModule(false) {}\n'
        else:
            header += '        explicit DynamicModule() = default;\n'

        for func in data['functions']:
            func_name = func['name']
            header += f'        {func_name} {func_name}{{}};\n'

        header += '\n        Int32Result Load() override {\n'
        if data['dll_names']:
            header += '            for (const auto& dll : DLL_NAMES) {\n'
            header += '                (void)api::DynamicModule::Unload();\n'
            header += '                api::DynamicModule::szDllName = dll;\n'
            header += '                const auto loadRet = api::DynamicModule::Load();\n'
            header += '                if (!loadRet) {\n'
            header += '                    continue;\n'
            header += '                }\n'
            header += '                bool ok = true;\n'
            header += '                bool any_loaded = false;\n'

            for func in data['functions']:
                func_name = func['name']
                func_type = f'::cpl::sys::api::{namespace_name}::{func_name}'
                if func['necessary']:
                    header += (
                        f'                const auto ret_{func_name} = '
                        f'api::DynamicModule::LoadFunction<{func_type}>("{func_name}");\n'
                    )
                else:
                    header += (
                        f'                const auto ret_{func_name} = '
                        f'api::DynamicModule::LoadFunction<{func_type}>("{func_name}", false);\n'
                    )
                header += f'                if (!ret_{func_name}) {{\n'
                if func['necessary']:
                    header += '                    ok = false;\n'
                header += '                } else {\n'
                header += '                    any_loaded = true;\n'
                header += f'                    {func_name} = ret_{func_name}.value<>();\n'
                header += '                }\n'

            header += '                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {\n'
            header += '                    return 0;\n'
            header += '                }\n'
            header += '            }\n'
            if data['necessary']:
                header += '            return Err(cpl::Error(cpl::Error::UnavailableAPI, "load module or function failed"));\n'
            else:
                header += '            return 0;\n'
        else:
            header += '            return 0;\n'

        header += '        }\n'
        header += '\n        Int32Result Unload() override {\n'
        for func in data['functions']:
            func_name = func['name']
            header += f'            {func_name} = nullptr;\n'
        header += '            const auto unloadRet = api::DynamicModule::Unload();\n'
        header += '            if (!unloadRet) {\n'
        header += '                return unloadRet;\n'
        header += '            }\n'
        header += '            return 0;\n'
        header += '        }\n'
        header += '    };\n'
        header += '}\n\n'

    tpl = r'''

class API final: public base::ISingleton<API> {
    friend class base::ISingleton<API>;
    API() = default;
    bool loaded{false};
public:
    /* wincrypt::DynamicModule wincrypt{}; */

    Int32Result Load() {
        if (!this->loaded) {
            this->loaded = true;
            /* m.wincrypt.Load(); */
            return 0;
        }
        return 0;
    }
};
'''
    buf1 = []
    buf2 = []
    for namespace_name in sub_namespaces:
        buf1.append(f'    {namespace_name}::DynamicModule {namespace_name}{{}};')
        buf2.append(
            f'            const auto ret_{namespace_name} = this->{namespace_name}.Load();\n'
            f'            if (!ret_{namespace_name}) {{\n'
            f'                return ret_{namespace_name};\n'
            f'            }}'
        )

    modules = tpl.replace(
        '    /* wincrypt::DynamicModule wincrypt{}; */',
        '\n'.join(buf1),
    ).replace(
        '        /* m.wincrypt.Load(); */',
        '\n'.join(buf2),
    )
    header += '\n\n\n' + modules + '\n\n\n'

    header += '} // namespace api\n'
    header += '} // namespace sys\n'
    header += '} // namespace cpl\n'
    return header


def main():
    base_dir = Path(__file__).resolve().parent
    sys_hpp = base_dir / 'sys.hpp'
    api_hpp = base_dir / 'api.hpp'

    sys_content = sys_hpp.read_text(encoding='utf-8')
    sub_namespaces = extract_namespace_structure(sys_content)
    api_content = generate_api_header(sub_namespaces)
    api_hpp.write_text(api_content, encoding='utf-8')
    print('api.hpp generated successfully!')


if __name__ == '__main__':
    main()
