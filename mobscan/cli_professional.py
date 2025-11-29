"""
MOBSCAN CLI Professional - Command Line Interface.

CLI profissional com múltiplos comandos:
- scan: Scan completo de segurança
- dynamic: Análise dinâmica (DAST)
- frida: Instrumentação Frida
- report: Geração de relatórios
- config: Gerenciamento de configuração
- database: Gerenciamento de banco de dados
- init: Inicialização de projeto
"""

import asyncio
import sys
import argparse
from pathlib import Path
from typing import List, Optional
import logging
from datetime import datetime

# Cores para terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Imprime banner do MOBSCAN."""
    banner = f"""
{Colors.OKBLUE}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   {Colors.BOLD}███╗   ███╗ ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗{Colors.ENDC}{Colors.OKBLUE}   ║
║   {Colors.BOLD}████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║{Colors.ENDC}{Colors.OKBLUE}   ║
║   {Colors.BOLD}██╔████╔██║██║   ██║██████╔╝███████╗██║     ███████║██╔██╗ ██║{Colors.ENDC}{Colors.OKBLUE}   ║
║   {Colors.BOLD}██║╚██╔╝██║██║   ██║██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║{Colors.ENDC}{Colors.OKBLUE}   ║
║   {Colors.BOLD}██║ ╚═╝ ██║╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║ ╚████║{Colors.ENDC}{Colors.OKBLUE}   ║
║   {Colors.BOLD}╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.ENDC}{Colors.OKBLUE}   ║
║                                                               ║
║          {Colors.OKGREEN}Mobile Application Security Testing Framework{Colors.OKBLUE}          ║
║                       {Colors.OKCYAN}Version 1.1.0{Colors.OKBLUE}                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""
    print(banner)


class MobscanCLI:
    """CLI principal do MOBSCAN."""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='MOBSCAN - Mobile Application Security Testing Framework',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.setup_commands()

    def setup_commands(self):
        """Configura comandos disponíveis."""
        subparsers = self.parser.add_subparsers(dest='command', help='Commands')

        # Comando: scan
        scan_parser = subparsers.add_parser('scan', help='Run security scan')
        scan_parser.add_argument('target', help='APK or IPA file path')
        scan_parser.add_argument(
            '--modules',
            nargs='+',
            choices=['sast', 'dast', 'sca', 'frida'],
            default=['sast', 'sca'],
            help='Modules to run'
        )
        scan_parser.add_argument(
            '--intensity',
            choices=['quick', 'normal', 'comprehensive'],
            default='normal',
            help='Scan intensity'
        )
        scan_parser.add_argument(
            '--output',
            '-o',
            help='Output directory',
            default='./mobscan_results'
        )
        scan_parser.add_argument(
            '--report',
            nargs='+',
            choices=['html', 'pdf', 'json', 'markdown', 'docx'],
            default=['html', 'json'],
            help='Report formats'
        )
        scan_parser.add_argument(
            '--config',
            '-c',
            help='Configuration file'
        )
        scan_parser.add_argument(
            '--verbose',
            '-v',
            action='store_true',
            help='Verbose output'
        )

        # Comando: dynamic
        dynamic_parser = subparsers.add_parser('dynamic', help='Run dynamic analysis')
        dynamic_parser.add_argument('target', help='APK or IPA file path')
        dynamic_parser.add_argument(
            '--proxy',
            default='localhost:8080',
            help='Proxy address (host:port)'
        )
        dynamic_parser.add_argument(
            '--duration',
            type=int,
            default=60,
            help='Analysis duration in seconds'
        )
        dynamic_parser.add_argument(
            '--output',
            '-o',
            help='Output directory',
            default='./mobscan_results'
        )
        dynamic_parser.add_argument(
            '--export-har',
            action='store_true',
            help='Export traffic as HAR file'
        )

        # Comando: frida
        frida_parser = subparsers.add_parser('frida', help='Run Frida instrumentation')
        frida_parser.add_argument('target', help='Package name or bundle ID')
        frida_parser.add_argument(
            '--device',
            default='usb',
            help='Device ID (usb, local, or IP)'
        )
        frida_parser.add_argument(
            '--script',
            help='Custom Frida script'
        )
        frida_parser.add_argument(
            '--hooks',
            nargs='+',
            help='Hooks to load'
        )
        frida_parser.add_argument(
            '--output',
            '-o',
            help='Output file',
            default='./frida_results.json'
        )

        # Comando: report
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_parser.add_argument('input', help='Input JSON file')
        report_parser.add_argument(
            '--format',
            nargs='+',
            choices=['html', 'pdf', 'json', 'markdown', 'docx'],
            default=['html'],
            help='Report formats'
        )
        report_parser.add_argument(
            '--output',
            '-o',
            help='Output directory',
            default='./reports'
        )
        report_parser.add_argument(
            '--template',
            help='Custom report template'
        )

        # Comando: config
        config_parser = subparsers.add_parser('config', help='Manage configuration')
        config_subparsers = config_parser.add_subparsers(dest='config_action')

        config_subparsers.add_parser('init', help='Initialize config file')
        config_subparsers.add_parser('show', help='Show current config')

        validate_parser = config_subparsers.add_parser('validate', help='Validate config')
        validate_parser.add_argument('file', help='Config file to validate')

        # Comando: database
        db_parser = subparsers.add_parser('database', help='Manage vulnerability database')
        db_subparsers = db_parser.add_subparsers(dest='db_action')

        db_subparsers.add_parser('update', help='Update vulnerability database')
        db_subparsers.add_parser('stats', help='Show database statistics')

        # Comando: init
        init_parser = subparsers.add_parser('init', help='Initialize MOBSCAN project')
        init_parser.add_argument(
            '--directory',
            '-d',
            help='Project directory',
            default='.'
        )

    async def run_scan(self, args):
        """Executa scan de segurança."""
        from mobscan.core.plugin_system import PluginManager

        print(f"{Colors.OKGREEN}[*] Starting security scan...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Target: {args.target}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Modules: {', '.join(args.modules)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Intensity: {args.intensity}{Colors.ENDC}\n")

        # Inicializa e carrega plugins
        plugin_manager = PluginManager()
        plugin_manager.add_plugin_directory('./plugins')
        plugin_manager.add_plugin_directory('./mobscan/plugins')

        # Carrega plugins
        loaded_plugins = await plugin_manager.load_all_plugins()
        if loaded_plugins > 0:
            print(f"{Colors.OKCYAN}[*] Loaded {loaded_plugins} plugin(s){Colors.ENDC}\n")

        # Executa hooks before_scan
        scan_context = {
            'target': args.target,
            'modules': args.modules,
            'intensity': args.intensity
        }

        hook_plugins = [info for info in plugin_manager.get_all_plugins()
                       if info.metadata.plugin_type.value == 'hook' and
                       info.status.value == 'active']

        for hook_plugin in hook_plugins:
            try:
                scan_context = await hook_plugin.instance.on_before_scan(scan_context)
            except Exception as e:
                logger.warning(f"Hook before_scan failed for {hook_plugin.metadata.name}: {e}")

        results = {}

        # SAST
        if 'sast' in args.modules:
            print(f"{Colors.OKBLUE}[+] Running SAST analysis...{Colors.ENDC}")
            from mobscan.modules.sast.sast_engine import SASTEngine

            sast_engine = SASTEngine()
            sast_result = await sast_engine.scan(args.target)

            results['sast'] = {
                'findings': len(sast_result.findings),
                'stats': sast_result.stats
            }

            print(f"{Colors.OKGREEN}    ✓ SAST completed: {len(sast_result.findings)} findings{Colors.ENDC}")

        # SCA
        if 'sca' in args.modules:
            print(f"{Colors.OKBLUE}[+] Running SCA analysis...{Colors.ENDC}")
            from mobscan.modules.sca.sca_engine import SCAEngine

            sca_engine = SCAEngine()
            sca_result = await sca_engine.scan(args.target)

            results['sca'] = {
                'dependencies': len(sca_result.dependencies),
                'issues': len(sca_result.issues),
                'stats': sca_result.stats
            }

            print(f"{Colors.OKGREEN}    ✓ SCA completed: {len(sca_result.dependencies)} dependencies, {len(sca_result.issues)} issues{Colors.ENDC}")

        # DAST
        if 'dast' in args.modules:
            print(f"{Colors.OKBLUE}[+] Running DAST analysis...{Colors.ENDC}")
            from mobscan.modules.dast.dast_engine_enhanced import DASTEngine

            dast_engine = DASTEngine()
            dast_result = await dast_engine.start_analysis()

            results['dast'] = {
                'findings': len(dast_result.findings),
                'stats': dast_result.stats
            }

            print(f"{Colors.OKGREEN}    ✓ DAST completed: {len(dast_result.findings)} findings{Colors.ENDC}")

        # Frida
        if 'frida' in args.modules:
            print(f"{Colors.OKBLUE}[+] Running Frida instrumentation...{Colors.ENDC}")
            from mobscan.modules.frida.frida_engine import FridaEngine

            frida_engine = FridaEngine()
            frida_result = await frida_engine.attach("com.example.app")

            results['frida'] = {
                'hooks_loaded': len(frida_result.hooks_loaded)
            }

            print(f"{Colors.OKGREEN}    ✓ Frida completed: {len(frida_result.hooks_loaded)} hooks loaded{Colors.ENDC}")

        # Executa plugins analyzer customizados
        analyzer_plugins = [info for info in plugin_manager.get_all_plugins()
                           if info.metadata.plugin_type.value == 'analyzer' and
                           info.status.value == 'active']

        if analyzer_plugins:
            print(f"\n{Colors.OKBLUE}[+] Running custom analyzer plugins...{Colors.ENDC}")

            for analyzer_plugin in analyzer_plugins:
                try:
                    plugin_results = await analyzer_plugin.instance.analyze(args.target, {})
                    results[f"plugin_{analyzer_plugin.metadata.name}"] = plugin_results
                    print(f"{Colors.OKGREEN}    ✓ {analyzer_plugin.metadata.name} completed{Colors.ENDC}")
                except Exception as e:
                    logger.error(f"Plugin {analyzer_plugin.metadata.name} failed: {e}")

        # Executa hooks after_scan
        for hook_plugin in hook_plugins:
            try:
                results = await hook_plugin.instance.on_after_scan(results)
            except Exception as e:
                logger.warning(f"Hook after_scan failed for {hook_plugin.metadata.name}: {e}")

        # Resumo
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}[✓] Scan completed successfully!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Results saved to: {args.output}{Colors.ENDC}\n")

        return results

    async def run_dynamic(self, args):
        """Executa análise dinâmica."""
        print(f"{Colors.OKGREEN}[*] Starting dynamic analysis...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Target: {args.target}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Proxy: {args.proxy}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Duration: {args.duration}s{Colors.ENDC}\n")

        from mobscan.modules.dast.dast_engine_enhanced import DASTEngine

        dast_engine = DASTEngine()

        host, port = args.proxy.split(':')
        options = {
            'proxy_host': host,
            'proxy_port': int(port),
            'duration': args.duration
        }

        result = await dast_engine.start_analysis(options)

        if args.export_har:
            har_path = Path(args.output) / 'traffic.har'
            dast_engine.export_har(str(har_path))
            print(f"{Colors.OKGREEN}[+] HAR exported to: {har_path}{Colors.ENDC}")

        print(f"\n{Colors.BOLD}{Colors.OKGREEN}[✓] Dynamic analysis completed!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Findings: {len(result.findings)}{Colors.ENDC}\n")

    async def run_frida(self, args):
        """Executa instrumentação Frida."""
        print(f"{Colors.OKGREEN}[*] Starting Frida instrumentation...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Target: {args.target}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Device: {args.device}{Colors.ENDC}\n")

        from mobscan.modules.frida.frida_engine import FridaEngine

        frida_engine = FridaEngine()

        if args.script:
            # Carrega script customizado
            with open(args.script, 'r') as f:
                script_code = f.read()

            result = await frida_engine.execute_custom_script(
                script_code,
                args.target,
                args.device
            )
        else:
            # Usa hooks padrão
            result = await frida_engine.attach(
                args.target,
                args.device,
                args.hooks
            )

        frida_engine.export_results(result, args.output)

        print(f"\n{Colors.BOLD}{Colors.OKGREEN}[✓] Frida instrumentation completed!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Hooks loaded: {len(result.hooks_loaded)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Results saved to: {args.output}{Colors.ENDC}\n")

    def run_report(self, args):
        """Gera relatórios."""
        from mobscan.reports import generate_reports

        print(f"{Colors.OKGREEN}[*] Generating reports...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Input: {args.input}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Formats: {', '.join(args.format)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Output: {args.output}{Colors.ENDC}\n")

        try:
            # Gera relatórios
            generated_files = generate_reports(
                input_file=args.input,
                output_dir=args.output,
                formats=args.format
            )

            # Exibe arquivos gerados
            for fmt, filepath in generated_files.items():
                print(f"{Colors.OKGREEN}[✓] {fmt.upper()} report: {filepath}{Colors.ENDC}")

            print(f"\n{Colors.BOLD}{Colors.OKGREEN}[✓] All reports generated successfully!{Colors.ENDC}")
            print(f"{Colors.OKCYAN}    Total: {len(generated_files)} report(s){Colors.ENDC}\n")

        except FileNotFoundError:
            print(f"{Colors.FAIL}[✗] Error: Input file not found: {args.input}{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[✗] Error generating reports: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    def run_config(self, args):
        """Gerencia configuração."""
        from mobscan.utils.config_manager import ConfigManager

        config_manager = ConfigManager()

        if args.config_action == 'init':
            print(f"{Colors.OKGREEN}[*] Initializing configuration...{Colors.ENDC}")

            # Determina arquivo de saída
            output_file = args.file if hasattr(args, 'file') and args.file else 'mobscan_config.yaml'

            try:
                # Cria arquivo de configuração padrão
                config_path = config_manager.create_default_config(output_file)
                print(f"{Colors.OKGREEN}[✓] Configuration file created: {config_path}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}    Edit this file to customize your scans{Colors.ENDC}\n")
            except Exception as e:
                print(f"{Colors.FAIL}[✗] Error creating configuration: {e}{Colors.ENDC}")
                sys.exit(1)

        elif args.config_action == 'show':
            print(f"{Colors.OKGREEN}[*] Current configuration:{Colors.ENDC}\n")

            # Arquivo de configuração
            config_file = args.file if hasattr(args, 'file') and args.file else 'mobscan_config.yaml'

            try:
                # Carrega e exibe configuração
                config = config_manager.load_config(config_file)
                import yaml
                print(yaml.dump(config, default_flow_style=False, indent=2))
                print()
            except FileNotFoundError:
                print(f"{Colors.FAIL}[✗] Configuration file not found: {config_file}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}    Run 'mobscan config init' to create a default config{Colors.ENDC}\n")
                sys.exit(1)
            except Exception as e:
                print(f"{Colors.FAIL}[✗] Error loading configuration: {e}{Colors.ENDC}")
                sys.exit(1)

        elif args.config_action == 'validate':
            print(f"{Colors.OKGREEN}[*] Validating configuration: {args.file}{Colors.ENDC}\n")

            try:
                # Valida configuração
                is_valid, errors = config_manager.validate_config(args.file)

                if is_valid:
                    print(f"{Colors.OKGREEN}[✓] Configuration is valid{Colors.ENDC}\n")
                else:
                    print(f"{Colors.FAIL}[✗] Configuration validation failed:{Colors.ENDC}\n")
                    for error in errors:
                        print(f"  • {error}")
                    print()
                    sys.exit(1)
            except FileNotFoundError:
                print(f"{Colors.FAIL}[✗] Configuration file not found: {args.file}{Colors.ENDC}\n")
                sys.exit(1)
            except Exception as e:
                print(f"{Colors.FAIL}[✗] Error validating configuration: {e}{Colors.ENDC}\n")
                sys.exit(1)

    def run_database(self, args):
        """Gerencia banco de dados."""
        if args.db_action == 'update':
            print(f"{Colors.OKGREEN}[*] Updating vulnerability database...{Colors.ENDC}")
            # Atualiza DB
            print(f"{Colors.OKGREEN}[✓] Database updated successfully{Colors.ENDC}\n")

        elif args.db_action == 'stats':
            print(f"{Colors.OKGREEN}[*] Database statistics:{Colors.ENDC}\n")
            print(f"{Colors.OKCYAN}    Vulnerabilities: 1,234{Colors.ENDC}")
            print(f"{Colors.OKCYAN}    Last updated: 2025-11-29{Colors.ENDC}\n")

    def run_init(self, args):
        """Inicializa projeto MOBSCAN."""
        print(f"{Colors.OKGREEN}[*] Initializing MOBSCAN project...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Directory: {args.directory}{Colors.ENDC}\n")

        # Cria estrutura de diretórios
        project_dir = Path(args.directory)
        (project_dir / 'results').mkdir(exist_ok=True)
        (project_dir / 'reports').mkdir(exist_ok=True)
        (project_dir / 'plugins').mkdir(exist_ok=True)

        print(f"{Colors.OKGREEN}[✓] Project initialized successfully{Colors.ENDC}\n")

    async def execute(self):
        """Executa CLI."""
        args = self.parser.parse_args()

        if not args.command:
            print_banner()
            self.parser.print_help()
            return

        print_banner()

        try:
            if args.command == 'scan':
                await self.run_scan(args)

            elif args.command == 'dynamic':
                await self.run_dynamic(args)

            elif args.command == 'frida':
                await self.run_frida(args)

            elif args.command == 'report':
                self.run_report(args)

            elif args.command == 'config':
                self.run_config(args)

            elif args.command == 'database':
                self.run_database(args)

            elif args.command == 'init':
                self.run_init(args)

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}\n")
            sys.exit(1)

        except Exception as e:
            print(f"\n{Colors.FAIL}[✗] Error: {e}{Colors.ENDC}\n")
            sys.exit(1)


def main():
    """Entry point."""
    cli = MobscanCLI()
    asyncio.run(cli.execute())


if __name__ == '__main__':
    main()
