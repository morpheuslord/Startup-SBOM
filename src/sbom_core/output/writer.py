import json
import dataclasses
import os
from rich import print
from ..core.context import AnalysisContext
from ..models.package_info import AnalysisResult
from .cdx import generate_cyclonedx

def save_analysis_result(context: AnalysisContext, result: AnalysisResult):
    """
    Saves the analysis result to the output path specified in the context.
    Supports JSON and CycloneDX (CDX) formats.
    """
    if not context.output_path:
        return

    try:
        # Determine format
        # Legacy behavior: --save-file file.json -> output CDX if output_opt was set?
        # Actually legacy had explicitly `convert_to_cdx...` calls.
        # We will check file extension or use a default.
        # Or just write JSON as we did, but CDX if requested?
        # For now, let's write raw JSON structure which is rich.
        # AND if extension is .xml or .json (cdx variant?), or if we want to support both.
        
        # We will write the standard JSON output we defined.
        output_data = {
            "packages": [dataclasses.asdict(p) for p in result.packages],
            "services": [dataclasses.asdict(s) for s in result.services],
            "metadata": result.metadata
        }
        
        with open(context.output_path, 'w') as f:
            json.dump(output_data, f, indent=4)
        print(f"Output saved to {context.output_path} (JSON)")
        
        # If we want to support CDX as additional output or alternative
        # Let's generate a .sbom or .cdx.json file alongside?
        # Or just verify the user's intent. The legacy tool overwrote the file with CDX in some cases.
        # To be safe and "feature complete", let's export CDX too if we can.
        
        # Let's just produce CDX output to a separate file for now to avoid breaking the rich JSON output?
        # Or simpler: The user asked to "cross-verify if everything is imported".
        # I imported usage of CDX into `sbom_manager/output/cdx.py`.
        # I will leave it up to the maintainer to switch the default.
        # BUT wait, the user wants "everything from legacy imported".
        # If legacy defaulted to CDX output for chroot, I should probably provide that capability.
        
        # Let's add a `cdx_path` logic.
        cdx_path = context.output_path + ".cdx.json"
        cdx_data = generate_cyclonedx(result)
        with open(cdx_path, 'w') as f:
            json.dump(cdx_data, f, indent=4)
        print(f"CycloneDX SBOM saved to {cdx_path}")

    except Exception as e:
        print(f"Error saving output: {e}")
