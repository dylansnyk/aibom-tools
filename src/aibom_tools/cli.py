"""
CLI module for aibom-tools
"""

import os
import sys
import json
import time
from typing import Optional, List, Set

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.spinner import Spinner
from rich.status import Status

from .config import Config
from .api import SnykAIBomAPIClient

console = Console()


def load_policy_file(policy_file_path: str) -> Set[str]:
    """
    Load and parse a YAML policy file to extract rejected models.
    
    Args:
        policy_file_path: Path to the YAML policy file
        
    Returns:
        Set of rejected model names
        
    Raises:
        click.ClickException: If the policy file cannot be parsed or is invalid
    """
    try:
        with open(policy_file_path, 'r') as f:
            policy_data = yaml.safe_load(f)
        
        if not isinstance(policy_data, dict):
            raise click.ClickException(f"Policy file must contain a YAML dictionary, got {type(policy_data)}")
        
        if 'reject' not in policy_data:
            raise click.ClickException("Policy file must contain a 'reject' key")
        
        reject_list = policy_data['reject']
        if not isinstance(reject_list, list):
            raise click.ClickException("'reject' key must contain a list of model names")
        
        # Convert to set for efficient lookup and normalize names
        rejected_models = set()
        for model in reject_list:
            if not isinstance(model, str):
                raise click.ClickException(f"All rejected models must be strings, got {type(model)}")
            rejected_models.add(model.strip().lower())
        
        return rejected_models
        
    except yaml.YAMLError as e:
        raise click.ClickException(f"Failed to parse YAML policy file: {e}")
    except FileNotFoundError:
        raise click.ClickException(f"Policy file not found: {policy_file_path}")
    except Exception as e:
        raise click.ClickException(f"Error reading policy file: {e}")


@click.group()
@click.version_option()
@click.option(
    "--api-token",
    envvar="SNYK_API_TOKEN",
    help="Snyk API token (can also be set via SNYK_API_TOKEN env var)",
)
@click.option(
    "--org-id",
    envvar="SNYK_ORG_ID",
    help="Snyk Organization ID (can also be set via SNYK_ORG_ID env var)",
)
@click.option(
    "--api-url",
    envvar="SNYK_API_URL",
    default="https://api.snyk.io",
    help="Snyk API base URL (defaults to https://api.snyk.io)",
)
@click.option(
    "--group-id",
    envvar="SNYK_GROUP_ID", 
    type=str,
    help="Snyk Group ID (can also be set via SNYK_GROUP_ID env var)",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug logging",
)
@click.pass_context
def cli(ctx: click.Context, api_token: Optional[str], org_id: Optional[str], group_id: Optional[str],
        api_url: str, debug: bool) -> None:
    """
    aibom-tools: CLI tool for generating AI Bill of Materials using Snyk API
    
    This tool helps you create AI BOMs for your projects using Snyk's AI-BOM API.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Store configuration in context
    config = Config(
        api_token=api_token,
        org_id=org_id,
        group_id=group_id,
        api_url=api_url,
        debug=debug
    )
    
    if not group_id and not org_id:
        console.print("[bold red]Error:[/bold red] Either --group-id or --org-id is required.")
        sys.exit(1)
    
    ctx.obj["config"] = config
    
    if debug:
        console.print("[bold blue]Debug mode enabled[/bold blue]")


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path for AI-BOMs",
)
@click.option(
    "--html",
    type=click.Path(),
    help="Output file path for HTML report",
)
@click.option(
    "--include",
    "-i",
    type=str,
    help="Comma-separated list of AI component types to include in the summary (e.g., 'ML Model,Application,Library')",
)
@click.option(
    "--policy-file",
    type=click.Path(exists=True, readable=True),
    help="Path to YAML policy file containing list of forbidden models",
)
@click.pass_context
def scan(
    ctx: click.Context,
    output: Optional[str],
    html: Optional[str],
    include: Optional[str],
    policy_file: Optional[str],
) -> None:
    """
    Create a new AI-BOM scan
    
    This command triggers a scan of all targets in the given Snyk organization.
    """
    config = ctx.obj["config"]
    
    # Load policy file if provided
    rejected_models = None
    if policy_file:
        try:
            rejected_models = load_policy_file(policy_file)
            console.print(f"[bold blue]📋 Policy file loaded: {len(rejected_models)} forbidden models[/bold blue]")
        except click.ClickException as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            sys.exit(1)
    
    # Validate required configuration
    if not config.api_token:
        console.print("[bold red]Error:[/bold red] API token is required. "
                     "Set SNYK_API_TOKEN environment variable or use --api-token option.")
        sys.exit(1)
        
    if not config.org_id:
        console.print("[bold red]Error:[/bold red] Organization ID is required. "
                     "Set SNYK_ORG_ID environment variable or use --org-id option.")
        sys.exit(1)
    
    # Create API client
    # client = SnykAIBOMClient(config)
    client = SnykAIBomAPIClient(config)
    try:
        # Animated status while retrieving targets
        with Status("[bold green]Retrieving targets...", spinner="dots") as status:
            all_targets = client.get_all_targets()
            all_aiboms = []
            
        if not all_targets:
            console.print("[bold red]❌ Could not retrieve any targets. Exiting.[/bold red]")
            sys.exit(1)
            
        if config.group_id:
            console.print(f"[bold blue]🎯 Found {len(all_targets)} total targets in the group {config.group_id}.[/bold blue]")
        else:
            console.print(f"[bold blue]🎯 Found {len(all_targets)} total targets in the organization {config.org_id}.[/bold blue]")
        
        # Filter targets to only supported ones for the progress bar
        supported_targets = []
        for target in all_targets:
            integration_type = target.get('relationships', {}).get('integration', {}).get('data', {}).get('attributes', {}).get('integration_type')
            if integration_type in ['github', 'github-enterprise', 'github-cloud-app', 'github-server-app', 'gitlab', 'azure-repos', 'bitbucket-cloud', 'bitbucket-server', 'bitbucket-cloud-app']:
                supported_targets.append(target)
        
        console.print(f"[bold cyan]📊 Processing {len(supported_targets)} supported targets...[/bold cyan]")
        
        # Progress bar for processing targets
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            main_task = progress.add_task("Scanning targets...", total=len(all_targets))
            
            for i, target in enumerate(all_targets):
                target_name = target['attributes'].get('display_name', 'Unknown Name')
                progress.update(main_task, description=f"Processing: {target_name[:30]}...")
                
                integration_type = target.get('relationships', {}).get('integration', {}).get('data', {}).get('attributes', {}).get('integration_type')
                if integration_type in ['github', 'github-enterprise', 'github-cloud-app', 'github-server-app', 'gitlab', 'azure-repos', 'bitbucket-cloud', 'bitbucket-server', 'bitbucket-cloud-app']:
                    aibom_data = client.process_target(target)
                    if aibom_data:
                        component_count = len(aibom_data['data']['attributes']['components']) - 1
                        console.print(f"  [bold green]✅[/bold green] {target_name}: [bold yellow]{component_count}[/bold yellow] AI components")
                        all_aiboms.append({ 
                            'target_name': target_name,
                            'aibom_data': aibom_data
                        })
                    else:
                        console.print(f"  [bold red]❌[/bold red] Error scanning {target_name}")
                else:
                    # Skip other target types like container images or manual uploads
                    console.print(f"  [dim]⏭️  Skipping {target_name} (unsupported type)[/dim]")
                
                progress.advance(main_task)
        
        # Animated completion message
        with console.status("[bold green]Generating comprehensive report...", spinner="arc"):
            time.sleep(1)  # Simulate processing time
        
        console.print("\n[bold green]🎉 Scan Complete![/bold green]")
        console.print("[bold blue]" + "=" * 50 + "[/bold blue]")
        
        # Display comprehensive summary of all AI components
        if all_aiboms:
            _display_aibom_summary_all(all_aiboms, include_types=include, rejected_models=rejected_models)
        else:
            console.print("[bold yellow]⚠️  No AI components found in any targets.[/bold yellow]")

        if output:
            output_data = {"all_aibom_data": all_aiboms}
            with open(output, 'w') as f:
                json.dump(output_data, f, indent=4)
            console.print(f"[bold green]📄 JSON report saved to: {output}[/bold green]")
        
        if html:
            html_content = _generate_html_report(all_aiboms, include_types=include, rejected_models=rejected_models)
            with open(html, 'w', encoding='utf-8') as f:
                f.write(html_content)
            console.print(f"[bold green]🌐 HTML report saved to: {html}[/bold green]")
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        if config.debug:
            console.print_exception()
        sys.exit(1)

def _display_aibom_summary_all(all_aiboms: list, include_types: Optional[str] = None, rejected_models: Optional[Set[str]] = None) -> None:
    """Display a comprehensive summary of all AI components across all targets"""
    if not all_aiboms:
        console.print("[yellow]No AI components found across any targets.[/yellow]")
        return
    
    # Parse and normalize include types if provided
    included_internal_types = None
    if include_types:
        # Create mapping from user-friendly names to internal types (case-insensitive)
        user_type_mapping = {
            'ml model': 'machine-learning-model',
            'ml models': 'machine-learning-model', 
            'machine learning model': 'machine-learning-model',
            'machine learning models': 'machine-learning-model',
            'dataset': 'data',
            'datasets': 'data',
            'data': 'data',
            'library': 'library',
            'libraries': 'library',
            'application': 'application',
            'applications': 'application',
            'app': 'application',
            'apps': 'application'
        }
        
        # Parse comma-separated types and convert to internal format
        include_list = [t.strip().lower() for t in include_types.split(',')]
        included_internal_types = set()
        
        for user_type in include_list:
            if user_type in user_type_mapping:
                included_internal_types.add(user_type_mapping[user_type])
            else:
                # Try direct match with internal types (for backward compatibility)
                if user_type in ['machine-learning-model', 'data', 'library', 'application']:
                    included_internal_types.add(user_type)
                else:
                    console.print(f"[bold yellow]Warning:[/bold yellow] Unknown component type '{user_type}' will be ignored")
        
        if not included_internal_types:
            console.print("[bold red]Error:[/bold red] No valid component types specified")
            return
    
    # Animated header
    with console.status("[bold green]Preparing AI Components Summary...", spinner="aesthetic"):
        time.sleep(0.5)
    
    console.print("\n[bold green]🤖 AI Components Summary - All Targets 🎯[/bold green]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("AI Component", style="cyan", no_wrap=False, min_width=40)
    table.add_column("Target Name", style="yellow", no_wrap=True, min_width=25)
    table.add_column("Type", style="blue", no_wrap=True, min_width=15)
    table.add_column("Locations", style="dim", no_wrap=False, min_width=30)
    
    # Collect all AI components across targets
    total_components = 0
    
    for target_info in all_aiboms:
        target_name = target_info.get('target_name', 'Unknown Target')
        aibom_data = target_info.get('aibom_data', {})
        
        # Handle both old format (data.attributes.components) and new format (components)
        if 'data' in aibom_data:
            components = aibom_data.get('data', {}).get('attributes', {}).get('components', [])
        else:
            components = aibom_data.get('components', [])
        
        for component in components:
            # Skip the Root application component as it's not a real AI component
            if (component.get('name') == 'Root' and 
                component.get('type') == 'application'):
                continue
            
            comp_type = component.get('type', 'unknown')
            
            # Filter by included types if specified
            if included_internal_types and comp_type not in included_internal_types:
                continue
            
            name = component.get('name', 'Unknown Component')
            
            # Format component type for better readability
            type_mapping = {
                'machine-learning-model': 'ML Model',
                'data': 'Dataset', 
                'library': 'Library',
                'application': 'Application'
            }
            formatted_type = type_mapping.get(comp_type, comp_type.title())
            
            # Extract location information from evidence
            locations = []
            evidence = component.get('evidence', {})
            occurrences = evidence.get('occurrences', [])
            
            for occurrence in occurrences:
                location = occurrence.get('location', '')
                line = occurrence.get('line', '')
                if location and line:
                    locations.append(f"{location}:{line}")
                elif location:
                    locations.append(location)
            
            # Format locations for display
            if locations:
                location_str = '\n'.join(locations[:3])  # Show max 3 locations
                if len(locations) > 3:
                    location_str += f'\n... and {len(locations) - 3} more'
            else:
                location_str = "No source locations"
            
            table.add_row(name, target_name, formatted_type, location_str)
            total_components += 1
    
    # Display the completed table
    console.print(table)
    
    # Animated completion statistics
    with console.status("[bold cyan]Calculating statistics...", spinner="moon"):
        time.sleep(0.3)
        
        # Print summary by type
        component_types = {}
        for target_info in all_aiboms:
            target_name = target_info.get('target_name', 'Unknown Target')
            aibom_data = target_info.get('aibom_data', {})
            
            if 'data' in aibom_data:
                components = aibom_data.get('data', {}).get('attributes', {}).get('components', [])
            else:
                components = aibom_data.get('components', [])
            
            for component in components:
                if (component.get('name') == 'Root' and 
                    component.get('type') == 'application'):
                    continue
                
                comp_type = component.get('type', 'unknown')
                
                # Filter by included types if specified
                if included_internal_types and comp_type not in included_internal_types:
                    continue
                
                component_types[comp_type] = component_types.get(comp_type, 0) + 1
    
    # Statistics panel
    console.print(f"\n[bold green]📈 Total AI Components Found: {total_components}[/bold green]")
    
    if component_types:
        console.print("\n[bold cyan]📊 Component Types Breakdown:[/bold cyan]")
        
        # Create a mini table for component types
        stats_table = Table(show_header=True, header_style="bold blue", box=None)
        stats_table.add_column("Type", style="cyan")
        stats_table.add_column("Count", style="green", justify="right")
        
        for comp_type, count in sorted(component_types.items()):
            type_mapping = {
                'machine-learning-model': '🧠 ML Models',
                'data': '📊 Datasets', 
                'library': '📚 Libraries',
                'application': '🔧 Applications'
            }
            formatted_type = type_mapping.get(comp_type, f"🔧 {comp_type.title()}")
            stats_table.add_row(formatted_type, str(count))
        
        console.print(stats_table)
    
    # Policy validation and forbidden models table
    if rejected_models:
        _display_policy_validation(all_aiboms, rejected_models)


def _display_policy_validation(all_aiboms: list, rejected_models: Set[str]) -> None:
    """Display policy validation results and forbidden models table"""
    # Collect all forbidden models found in the scan
    forbidden_found = []
    
    for target_info in all_aiboms:
        target_name = target_info.get('target_name', 'Unknown Target')
        aibom_data = target_info.get('aibom_data', {})
        
        # Handle both old format (data.attributes.components) and new format (components)
        if 'data' in aibom_data:
            components = aibom_data.get('data', {}).get('attributes', {}).get('components', [])
        else:
            components = aibom_data.get('components', [])
        
        for component in components:
            # Skip the Root application component as it's not a real AI component
            if (component.get('name') == 'Root' and 
                component.get('type') == 'application'):
                continue
            
            # Only check ML models for policy violations
            if component.get('type') != 'machine-learning-model':
                continue
            
            model_name = component.get('name', '').strip().lower()
            
            # Check if this model is in the rejected list
            if model_name in rejected_models:
                # Extract location information from evidence
                locations = []
                evidence = component.get('evidence', {})
                occurrences = evidence.get('occurrences', [])
                
                for occurrence in occurrences:
                    location = occurrence.get('location', '')
                    line = occurrence.get('line', '')
                    if location and line:
                        locations.append(f"{location}:{line}")
                    elif location:
                        locations.append(location)
                
                # Format locations for display
                if locations:
                    location_str = '\n'.join(locations[:3])  # Show max 3 locations
                    if len(locations) > 3:
                        location_str += f'\n... and {len(locations) - 3} more'
                else:
                    location_str = "No source locations"
                
                forbidden_found.append({
                    'model_name': component.get('name', 'Unknown Model'),
                    'target_name': target_name,
                    'locations': location_str
                })
    
    # Display results
    console.print("\n[bold red]🚫 Policy Validation Results[/bold red]")
    console.print("[bold blue]" + "=" * 50 + "[/bold blue]")
    
    if forbidden_found:
        # Create table for forbidden models
        forbidden_table = Table(show_header=True, header_style="bold red")
        forbidden_table.add_column("Forbidden Model", style="red", no_wrap=False, min_width=40)
        forbidden_table.add_column("Target Name", style="yellow", no_wrap=True, min_width=25)
        forbidden_table.add_column("Locations", style="dim", no_wrap=False, min_width=30)
        
        for item in forbidden_found:
            forbidden_table.add_row(
                item['model_name'],
                item['target_name'],
                item['locations']
            )
        
        console.print(forbidden_table)
        console.print(f"\n[bold red]❌ Policy Violation: {len(forbidden_found)} forbidden model(s) found![/bold red]")
    else:
        console.print("[bold green]✅ Policy Compliance: No forbidden models found in the scan![/bold green]")
        console.print("[bold blue]📋 All models in use comply with the provided policy.[/bold blue]")


def _generate_html_report(all_aiboms: list, include_types: Optional[str] = None, rejected_models: Optional[Set[str]] = None) -> str:
    """Generate an HTML report of all AI components across all targets"""
    if not all_aiboms:
        return _generate_empty_html_report()
    
    # Parse and normalize include types if provided (same logic as _display_aibom_summary_all)
    included_internal_types = None
    if include_types:
        user_type_mapping = {
            'ml model': 'machine-learning-model',
            'ml models': 'machine-learning-model', 
            'machine learning model': 'machine-learning-model',
            'machine learning models': 'machine-learning-model',
            'dataset': 'data',
            'datasets': 'data',
            'data': 'data',
            'library': 'library',
            'libraries': 'library',
            'application': 'application',
            'applications': 'application',
            'app': 'application',
            'apps': 'application'
        }
        
        include_list = [t.strip().lower() for t in include_types.split(',')]
        included_internal_types = set()
        
        for user_type in include_list:
            if user_type in user_type_mapping:
                included_internal_types.add(user_type_mapping[user_type])
            else:
                if user_type in ['machine-learning-model', 'data', 'library', 'application']:
                    included_internal_types.add(user_type)
    
    # Collect all AI components across targets
    components_data = []
    component_types = {}
    total_components = 0
    
    for target_info in all_aiboms:
        target_name = target_info.get('target_name', 'Unknown Target')
        aibom_data = target_info.get('aibom_data', {})
        
        # Handle both old format (data.attributes.components) and new format (components)
        if 'data' in aibom_data:
            components = aibom_data.get('data', {}).get('attributes', {}).get('components', [])
        else:
            components = aibom_data.get('components', [])
        
        for component in components:
            # Skip the Root application component as it's not a real AI component
            if (component.get('name') == 'Root' and 
                component.get('type') == 'application'):
                continue
            
            comp_type = component.get('type', 'unknown')
            
            # Filter by included types if specified
            if included_internal_types and comp_type not in included_internal_types:
                continue
            
            name = component.get('name', 'Unknown Component')
            
            # Format component type for better readability
            type_mapping = {
                'machine-learning-model': 'ML Model',
                'data': 'Dataset', 
                'library': 'Library',
                'application': 'Application'
            }
            formatted_type = type_mapping.get(comp_type, comp_type.title())
            
            # Extract location information from evidence
            locations = []
            evidence = component.get('evidence', {})
            occurrences = evidence.get('occurrences', [])
            
            for occurrence in occurrences:
                location = occurrence.get('location', '')
                line = occurrence.get('line', '')
                if location and line:
                    locations.append(f"{location}:{line}")
                elif location:
                    locations.append(location)
            
            # Format locations for display
            if locations:
                location_str = '; '.join(locations[:5])  # Show max 5 locations
                if len(locations) > 5:
                    location_str += f' ... and {len(locations) - 5} more'
            else:
                location_str = "No source locations"
            
            components_data.append({
                'name': name,
                'target_name': target_name,
                'type': formatted_type,
                'locations': location_str
            })
            
            component_types[comp_type] = component_types.get(comp_type, 0) + 1
            total_components += 1
    
    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Bill of Materials Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }}
        .stat-item {{
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .table-container {{
            padding: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .type-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .type-ml-model {{
            background: #e3f2fd;
            color: #1976d2;
        }}
        .type-dataset {{
            background: #f3e5f5;
            color: #7b1fa2;
        }}
        .type-library {{
            background: #e8f5e8;
            color: #388e3c;
        }}
        .type-application {{
            background: #fff3e0;
            color: #f57c00;
        }}
        .locations {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
            color: #666;
            max-width: 300px;
            word-break: break-all;
        }}
        .footer {{
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e9ecef;
            background: #f8f9fa;
        }}
        .no-data {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        .no-data h2 {{
            color: #999;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI Bill of Materials Report</h1>
            <p>Comprehensive analysis of AI components across all targets</p>
        </div>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number">{total_components}</div>
                <div class="stat-label">Total AI Components</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{len(all_aiboms)}</div>
                <div class="stat-label">Targets Scanned</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{len(component_types)}</div>
                <div class="stat-label">Component Types</div>
            </div>
        </div>
        
        <div class="table-container">
            {_generate_policy_validation_html(all_aiboms, rejected_models) if rejected_models else ''}
            
            {_generate_component_types_breakdown_html(component_types)}
            
            {_generate_components_table_html(components_data) if components_data else _generate_no_data_html()}
            
            {_generate_repositories_list_html(all_aiboms)}
        </div>
        
        <div class="footer">
            <p>Generated by aibom-tools • {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
    
    return html_content

def _generate_empty_html_report() -> str:
    """Generate HTML report when no AI components are found"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Bill of Materials Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .no-data {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        .no-data h2 {{
            color: #999;
            margin-bottom: 10px;
        }}
        .footer {{
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e9ecef;
            background: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI Bill of Materials Report</h1>
            <p>Comprehensive analysis of AI components across all targets</p>
        </div>
        
        <div class="no-data">
            <h2>⚠️ No AI Components Found</h2>
            <p>No AI components were detected in any of the scanned targets.</p>
        </div>
        
        <div class="footer">
            <p>Generated by aibom-tools • {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""

def _generate_component_types_breakdown_html(component_types: dict) -> str:
    """Generate HTML for component types breakdown"""
    if not component_types:
        return ""
    
    type_mapping = {
        'machine-learning-model': ('🧠 ML Models', 'type-ml-model'),
        'data': ('📊 Datasets', 'type-dataset'), 
        'library': ('📚 Libraries', 'type-library'),
        'application': ('🔧 Applications', 'type-application')
    }
    
    breakdown_html = '<h3>📊 Component Types Breakdown</h3><div style="display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap;">'
    
    for comp_type, count in sorted(component_types.items()):
        formatted_type, css_class = type_mapping.get(comp_type, (f"🔧 {comp_type.title()}", 'type-application'))
        breakdown_html += f'''
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; min-width: 120px;">
            <div style="font-size: 1.5em; font-weight: bold; color: #667eea;">{count}</div>
            <div style="color: #666; font-size: 0.9em;">{formatted_type}</div>
        </div>'''
    
    breakdown_html += '</div>'
    return breakdown_html

def _generate_components_table_html(components_data: list) -> str:
    """Generate HTML table for components data"""
    if not components_data:
        return _generate_no_data_html()
    
    table_html = '''
    <h3>🔍 AI Components Details</h3>
    <table>
        <thead>
            <tr>
                <th>AI Component</th>
                <th>Target Name</th>
                <th>Type</th>
                <th>Locations</th>
            </tr>
        </thead>
        <tbody>'''
    
    for component in components_data:
        # Determine CSS class for type badge
        type_class = 'type-application'  # default
        if 'ML Model' in component['type']:
            type_class = 'type-ml-model'
        elif 'Dataset' in component['type']:
            type_class = 'type-dataset'
        elif 'Library' in component['type']:
            type_class = 'type-library'
        
        table_html += f'''
            <tr>
                <td><strong>{component['name']}</strong></td>
                <td>{component['target_name']}</td>
                <td><span class="type-badge {type_class}">{component['type']}</span></td>
                <td class="locations">{component['locations']}</td>
            </tr>'''
    
    table_html += '''
        </tbody>
    </table>'''
    
    return table_html

def _generate_no_data_html() -> str:
    """Generate HTML for when no components are found"""
    return '''
    <div class="no-data">
        <h2>⚠️ No AI Components Found</h2>
        <p>No AI components were detected in any of the scanned targets.</p>
    </div>'''


def _generate_policy_validation_html(all_aiboms: list, rejected_models: Set[str]) -> str:
    """Generate HTML for policy validation results"""
    # Collect all forbidden models found in the scan (same logic as _display_policy_validation)
    forbidden_found = []
    
    for target_info in all_aiboms:
        target_name = target_info.get('target_name', 'Unknown Target')
        aibom_data = target_info.get('aibom_data', {})
        
        # Handle both old format (data.attributes.components) and new format (components)
        if 'data' in aibom_data:
            components = aibom_data.get('data', {}).get('attributes', {}).get('components', [])
        else:
            components = aibom_data.get('components', [])
        
        for component in components:
            # Skip the Root application component as it's not a real AI component
            if (component.get('name') == 'Root' and 
                component.get('type') == 'application'):
                continue
            
            # Only check ML models for policy violations
            if component.get('type') != 'machine-learning-model':
                continue
            
            model_name = component.get('name', '').strip().lower()
            
            # Check if this model is in the rejected list
            if model_name in rejected_models:
                # Extract location information from evidence
                locations = []
                evidence = component.get('evidence', {})
                occurrences = evidence.get('occurrences', [])
                
                for occurrence in occurrences:
                    location = occurrence.get('location', '')
                    line = occurrence.get('line', '')
                    if location and line:
                        locations.append(f"{location}:{line}")
                    elif location:
                        locations.append(location)
                
                # Format locations for display
                if locations:
                    location_str = '; '.join(locations[:5])  # Show max 5 locations
                    if len(locations) > 5:
                        location_str += f' ... and {len(locations) - 5} more'
                else:
                    location_str = "No source locations"
                
                forbidden_found.append({
                    'model_name': component.get('name', 'Unknown Model'),
                    'target_name': target_name,
                    'locations': location_str
                })
    
    # Generate HTML content
    if forbidden_found:
        # Policy violation HTML
        html_content = '''
        <h3 style="color: #d32f2f; margin-top: 30px;">🚫 Policy Validation Results</h3>
        <div style="background: #ffebee; border: 1px solid #f44336; border-radius: 8px; padding: 20px; margin: 20px 0;">
            <h4 style="color: #d32f2f; margin: 0 0 15px 0;">❌ Policy Violation: ''' + str(len(forbidden_found)) + ''' forbidden model(s) found!</h4>
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: #f44336; color: white;">
                        <th style="padding: 12px; text-align: left;">Forbidden Model</th>
                        <th style="padding: 12px; text-align: left;">Target Name</th>
                        <th style="padding: 12px; text-align: left;">Locations</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for item in forbidden_found:
            html_content += f'''
                    <tr style="border-bottom: 1px solid #e0e0e0;">
                        <td style="padding: 12px;"><strong style="color: #d32f2f;">{item['model_name']}</strong></td>
                        <td style="padding: 12px;">{item['target_name']}</td>
                        <td style="padding: 12px; font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; font-size: 0.9em; color: #666;">{item['locations']}</td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>
        </div>'''
        
        return html_content
    else:
        # Policy compliance HTML
        return '''
        <h3 style="color: #2e7d32; margin-top: 30px;">🚫 Policy Validation Results</h3>
        <div style="background: #e8f5e8; border: 1px solid #4caf50; border-radius: 8px; padding: 20px; margin: 20px 0;">
            <h4 style="color: #2e7d32; margin: 0 0 10px 0;">✅ Policy Compliance: No forbidden models found in the scan!</h4>
            <p style="color: #2e7d32; margin: 0;">📋 All models in use comply with the provided policy.</p>
        </div>'''


def _generate_repositories_list_html(all_aiboms: list) -> str:
    """Generate HTML for the list of successfully scanned repositories"""
    if not all_aiboms:
        return ""
    
    # Extract repository names and count AI components for each
    repositories_data = []
    for target_info in all_aiboms:
        target_name = target_info.get('target_name', 'Unknown Target')
        aibom_data = target_info.get('aibom_data', {})
        
        # Handle both old format (data.attributes.components) and new format (components)
        if 'data' in aibom_data:
            components = aibom_data.get('data', {}).get('attributes', {}).get('components', [])
        else:
            components = aibom_data.get('components', [])
        
        # Count AI components (excluding the Root application component)
        ai_component_count = 0
        for component in components:
            if not (component.get('name') == 'Root' and component.get('type') == 'application'):
                ai_component_count += 1
        
        repositories_data.append({
            'name': target_name,
            'ai_component_count': ai_component_count
        })
    
    # Sort repositories by name for consistent ordering
    repositories_data.sort(key=lambda x: x['name'].lower())
    
    # Generate HTML content
    html_content = '''
    <h3 style="color: #1976d2; margin-top: 40px; margin-bottom: 20px;">📁 Successfully Scanned Repositories</h3>
    <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin: 20px 0;">
        <p style="color: #666; margin: 0 0 15px 0; font-size: 0.95em;">The following repositories were successfully scanned for AI components:</p>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 10px;">'''
    
    for repo in repositories_data:
        html_content += f'''
        <div style="background: white; border: 1px solid #e0e0e0; border-radius: 6px; padding: 12px; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: 500; color: #333;">{repo['name']}</span>
            <span style="background: #e3f2fd; color: #1976d2; padding: 4px 8px; border-radius: 12px; font-size: 0.85em; font-weight: 600;">
                {repo['ai_component_count']} AI component{'' if repo['ai_component_count'] == 1 else 's'}
            </span>
        </div>'''
    
    html_content += '''
        </div>
        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0; text-align: center;">
            <span style="color: #666; font-size: 0.9em;">
                Total: <strong>''' + str(len(repositories_data)) + '''</strong> repositories scanned
            </span>
        </div>
    </div>'''
    
    return html_content

def main() -> None:
    """Main entry point for the CLI"""
    cli()


def scan_main() -> None:
    """Direct entry point for the scan command"""
    sys.argv = ["aibom-tools", "scan"] + sys.argv[1:]
    cli()


if __name__ == "__main__":
    main()
