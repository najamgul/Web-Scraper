"""
Clear all enrichment cache from the database
"""
from app import create_app
from app.models import IOCResult

app = create_app()

with app.app_context():
    print(" Clearing all enrichment cache from database...")
    
    # Count how many have enrichment
    total_iocs = IOCResult.objects.count()
    iocs_with_enrichment = IOCResult.objects(enrichment_context__exists=True, enrichment_context__ne=None).count()
    
    print(f" Total IOCs: {total_iocs}")
    print(f" IOCs with enrichment cache: {iocs_with_enrichment}")
    
    if iocs_with_enrichment > 0:
        # Clear enrichment_context field from all IOCs
        result = IOCResult.objects.update(enrichment_context=None)
        print(f" Cleared enrichment cache from {result} IOC records")
    else:
        print(" No enrichment cache found to clear")
    
    print("\n Cache clearing complete!")
    print(" Tip: Refresh your results page to generate fresh AI analysis")
