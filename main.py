import sys
from discovery import run_scanner
from visualisation import display_cli_table, generate_analytics_charts, export_plain_text

def main():
    print("Initializing Modular Passive Network Auditing Engine...\n")
    
    # Run scanner and process raw data pipelines
    scan_results = run_scanner()
    
    if not scan_results:
        print("Fatal Error: Could not parse or collect active telemetry points.")
        sys.exit(1)
        
    # Print the terminal workspace dashboard
    display_cli_table(scan_results)
    
    # Generate charts
    generate_analytics_charts(scan_results)
    
    # Save text asset
    export_plain_text(scan_results)
    
    print("\nEnvironment scanning and report generation sequences complete.")

if __name__ == "__main__":
    main()