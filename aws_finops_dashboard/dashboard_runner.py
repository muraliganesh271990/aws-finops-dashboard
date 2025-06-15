import argparse
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import boto3
from rich import box
from rich.console import Console
from rich.progress import track
from rich.status import Status
from rich.table import Column, Table

from aws_finops_dashboard.aws_client import (
    get_accessible_regions,
    get_account_id,
    get_aws_profiles,
    get_budgets,
    get_stopped_instances,
    get_untagged_resources,
    get_unused_eips,
    get_unused_volumes,
)
from aws_finops_dashboard.cost_processor import (
    export_to_csv,
    export_to_json,
    get_cost_data,
    get_trend,
)
from aws_finops_dashboard.helpers import (
    clean_rich_tags,
    export_audit_report_to_pdf,
    export_cost_dashboard_to_pdf,
    export_audit_report_to_csv,
    export_audit_report_to_json,
    export_trend_data_to_json,
)
from aws_finops_dashboard.profile_processor import (
    process_combined_profiles,
    process_single_profile,
)
from aws_finops_dashboard.types import ProfileData
from aws_finops_dashboard.visualisations import create_trend_bars

console = Console()

def _run_audit_report(profiles_to_use: List[str], args: argparse.Namespace) -> None:
    console.print("[bold bright_cyan]Preparing your audit report...[/]")
    table = Table(
        Column("Profile", justify="center"),
        Column("Account ID", justify="center"),
        Column("Untagged Resources"),
        Column("Stopped EC2 Instances"),
        Column("Unused Volumes"),
        Column("Unused EIPs"),
        Column("Budget Alerts"),
        Column("S3 Class Usage & Lifecycle"),
        Column("Compute Optimizer"),
        Column("RDS Storage & Idle Check"),
        Column("Unused Snapshots"),
        Column("Reserved Instance Usage"),
        Column("IAM Analysis"),
        Column("CloudWatch Storage Analysis"),
        Column("Scheduling Opportunities"),
        title="AWS FinOps Audit Report",
        show_lines=True,
        box=box.ASCII_DOUBLE_HEAD,
        style="bright_cyan",
    )

    audit_data = []
    raw_audit_data = []
    nl = "\n"
    comma_nl = ",\n"

    for profile in profiles_to_use:
        session = boto3.Session(profile_name=profile)
        account_id = get_account_id(session) or "Unknown"
        regions = args.regions or get_accessible_regions(session)

        try:
            untagged = get_untagged_resources(session, regions)
            anomalies = []
            for service, region_map in untagged.items():
                if region_map:
                    service_block = f"[bright_yellow]{service}[/]:\n"
                    for region, ids in region_map.items():
                        if ids:
                            ids_block = "\n".join(
                                f"[orange1]{res_id}[/]" for res_id in ids
                            )
                            service_block += f"\n{region}:\n{ids_block}\n"
                    anomalies.append(service_block)
            if not any(region_map for region_map in untagged.values()):
                anomalies = ["None"]
        except Exception as e:
            anomalies = [f"Error: {str(e)}"]

        stopped = get_stopped_instances(session, regions)
        stopped_list = [
            f"{r}:\n[gold1]{nl.join(ids)}[/]" for r, ids in stopped.items()
        ] or ["None"]

        unused_vols = get_unused_volumes(session, regions)
        vols_list = [
            f"{r}:\n[dark_orange]{nl.join(ids)}[/]" for r, ids in unused_vols.items()
        ] or ["None"]

        unused_eips = get_unused_eips(session, regions)
        eips_list = [
            f"{r}:\n{comma_nl.join(ids)}" for r, ids in unused_eips.items()
        ] or ["None"]

        budget_data = get_budgets(session)
        alerts = []
        for b in budget_data:
            if b["actual"] > b["limit"]:
                alerts.append(
                    f"[red1]{b['name']}[/]: ${b['actual']:.2f} > ${b['limit']:.2f}"
                )
        if not alerts:
            alerts = ["No budgets exceeded"]

        # --------- NEW: Placeholder values for new columns ---------
        s3_class_usage = ""  # TODO: get_s3_class_usage(session, regions)
        compute_optimizer = ""  # TODO: get_compute_optimizer(session, regions)
        rds_storage_idle = ""  # TODO: get_rds_storage_idle(session, regions)
        unused_snapshots = ""  # TODO: get_unused_snapshots(session, regions)
        reserved_instance_usage = ""  # TODO: get_reserved_instance_usage(session, regions)
        iam_analysis = ""  # TODO: get_iam_analysis(session, regions)
        cloudwatch_storage_analysis = ""  # TODO: get_cloudwatch_storage_analysis(session, regions)
        scheduling_opportunities = ""  # TODO: get_scheduling_opportunities(session, regions)

        audit_data.append(
            {
                "profile": profile,
                "account_id": account_id,
                "untagged_resources": clean_rich_tags("\n".join(anomalies)),
                "stopped_instances": clean_rich_tags("\n".join(stopped_list)),
                "unused_volumes": clean_rich_tags("\n".join(vols_list)),
                "unused_eips": clean_rich_tags("\n".join(eips_list)),
                "budget_alerts": clean_rich_tags("\n".join(alerts)),
                "s3_class_usage_and_lifecycle": s3_class_usage,
                "compute_optimizer": compute_optimizer,
                "rds_storage_and_idle_check": rds_storage_idle,
                "unused_snapshots": unused_snapshots,
                "reserved_instance_usage": reserved_instance_usage,
                "iam_analysis": iam_analysis,
                "cloudwatch_storage_analysis": cloudwatch_storage_analysis,
                "scheduling_opportunities": scheduling_opportunities,
            }
        )

        raw_audit_data.append(
            {
                "profile": profile,
                "account_id": account_id,
                "untagged_resources": untagged,
                "stopped_instances": stopped,
                "unused_volumes": unused_vols,
                "unused_eips": unused_eips,
                "budget_alerts": budget_data,
                "s3_class_usage_and_lifecycle": s3_class_usage,
                "compute_optimizer": compute_optimizer,
                "rds_storage_and_idle_check": rds_storage_idle,
                "unused_snapshots": unused_snapshots,
                "reserved_instance_usage": reserved_instance_usage,
                "iam_analysis": iam_analysis,
                "cloudwatch_storage_analysis": cloudwatch_storage_analysis,
                "scheduling_opportunities": scheduling_opportunities,
            }
        )

        table.add_row(
            f"[dark_magenta]{profile}[/]",
            account_id,
            "\n".join(anomalies),
            "\n".join(stopped_list),
            "\n".join(vols_list),
            "\n".join(eips_list),
            "\n".join(alerts),
            s3_class_usage,
            compute_optimizer,
            rds_storage_idle,
            unused_snapshots,
            reserved_instance_usage,
            iam_analysis,
            cloudwatch_storage_analysis,
            scheduling_opportunities,
        )
    console.print(table)
    console.print(
        "[bold bright_cyan]Note: The dashboard only lists untagged EC2, RDS, Lambda, ELBv2.\n[/]"
    )

    if args.report_name:
        if args.report_type:
            for report_type in args.report_type:
                if report_type == "csv":
                    csv_path = export_audit_report_to_csv(
                        audit_data, args.report_name, args.dir
                    )
                    if csv_path:
                        console.print(
                            f"[bright_green]Successfully exported to CSV format: {csv_path}[/]"
                        )
                elif report_type == "json":
                    json_path = export_audit_report_to_json(
                        raw_audit_data, args.report_name, args.dir
                    )
                    if json_path:
                        console.print(
                            f"[bright_green]Successfully exported to JSON format: {json_path}[/]"
                        )
                elif report_type == "pdf":
                    pdf_path = export_audit_report_to_pdf(
                        audit_data, args.report_name, args.dir
                    )
                    if pdf_path:
                        console.print(
                            f"[bright_green]Successfully exported to PDF format: {pdf_path}[/]"
                        )

def run_dashboard(args: argparse.Namespace) -> int:
    # ...rest of your dashboard logic...
    # This function must exist for CLI/main.py!
    pass  # Replace with your actual dashboard logic
