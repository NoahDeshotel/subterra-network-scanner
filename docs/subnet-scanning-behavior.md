# Network Subnet Scanning Behavior

## Overview
The network scanner intelligently handles different subnet sizes to balance performance and coverage. This document explains how the scanner behaves with various network sizes and scan modes.

## Scan Modes

The scanner supports three scan modes:

1. **Smart Mode**: Quick scanning with priority targeting
   - Scans only high-priority subnets
   - Best for quick network discovery
   - Minimal resource usage

2. **Thorough Mode**: Comprehensive scanning
   - Scans all subnets in the network
   - Provides complete network coverage
   - Balanced resource usage

3. **Full Mode**: Complete exhaustive scanning
   - Scans every subnet without filtering
   - Maximum coverage guarantee
   - Higher resource usage

## Automatic Mode Selection

When no scan mode is explicitly specified, the API automatically selects the appropriate mode based on network size:

| Network Size | Auto-Selected Mode | Reasoning |
|--------------|-------------------|-----------|
| /24 or smaller | Full | Small network, complete scan is fast |
| /20 to /23 | Thorough | Medium network, comprehensive scan is feasible |
| /16 | Thorough | Large network, comprehensive scan for full coverage |
| /15 or larger | Smart | Very large network, targeted scanning needed |

## Subnet Breakdown by Network Size

### /24 Network (256 addresses)
- **All modes**: Scans as single subnet
- **Hosts scanned**: Up to 254
- **Typical duration**: < 1 minute

### /16 Network (65,536 addresses)
- **Smart mode**: Scans ~20 priority /24 subnets
  - Priority subnets: .0.x, .1.x, .2.x, .10.x, .100.x, .254.x, etc.
  - Hosts scanned: ~5,000
  - Typical duration: 2-5 minutes
  
- **Thorough mode**: Scans ALL 256 /24 subnets
  - Complete network coverage
  - Hosts scanned: Up to 65,534
  - Typical duration: 15-30 minutes
  
- **Full mode**: Scans ALL 256 /24 subnets
  - No subnet filtering or probing
  - Hosts scanned: Up to 65,534
  - Typical duration: 15-30 minutes

### /20 Network (4,096 addresses)
- **All modes**: Scans all 16 /24 subnets
- **Hosts scanned**: Up to 4,094
- **Typical duration**: 2-5 minutes

## API Usage Examples

### Basic scan (auto mode selection)
```json
POST /api/scan/start
{
  "subnet": "10.0.0.0/16"
}
// Auto-selects 'thorough' mode for /16
```

### Explicit smart scan (fast, priority only)
```json
POST /api/scan/start
{
  "subnet": "10.0.0.0/16",
  "scan_mode": "smart"
}
// Scans only ~20 priority subnets
```

### Explicit full scan (complete coverage)
```json
POST /api/scan/start
{
  "subnet": "10.0.0.0/16",
  "scan_mode": "full"
}
// Scans ALL 256 subnets
```

### Comprehensive scan flag
```json
POST /api/scan/start
{
  "subnet": "10.0.0.0/16",
  "full_scan": true
}
// Forces 'full' mode regardless of network size
```

## Performance Considerations

### Threading and Concurrency
- The scanner uses thread pools for concurrent host scanning
- Default: 50 concurrent threads per subnet
- For /16 networks in full mode: processes 20 subnets in parallel batches

### Network Impact
- **Smart mode**: Minimal network impact, suitable for production
- **Thorough mode**: Moderate impact, suitable for maintenance windows
- **Full mode**: Higher impact, recommended for off-hours or dedicated scanning

### Scan Duration Estimates
These are approximate times for a typical network:

| Network | Smart Mode | Thorough Mode | Full Mode |
|---------|------------|---------------|-----------|
| /24 | 30s | 30s | 30s |
| /20 | 2 min | 2 min | 2 min |
| /16 | 3 min | 20 min | 20 min |
| /8 | 5 min | N/A* | N/A* |

*Very large networks are limited to prevent excessive scanning

## Frontend Integration

The frontend automatically selects appropriate scan modes:

- **Quick Scan**: Uses smart mode
- **Comprehensive Scan**: Uses full mode  
- **Emergency Scan**: Uses full mode with enhanced scanning

## Troubleshooting

### Issue: Scan only finding devices in first subnet
**Solution**: Ensure scan_mode is set to 'thorough' or 'full' for large networks

### Issue: Scan taking too long
**Solution**: Use 'smart' mode for faster results with priority targeting

### Issue: Missing devices in scan
**Solution**: Use 'thorough' or 'full' mode for complete coverage

## Best Practices

1. **For routine monitoring**: Use smart mode with scheduled scans
2. **For initial discovery**: Use thorough mode for comprehensive coverage
3. **For security audits**: Use full mode for guaranteed complete scanning
4. **For large networks (/8)**: Always use smart mode unless absolutely necessary

## Configuration Tips

### Environment Variables
```bash
# Force specific scan mode for all scans
export DEFAULT_SCAN_MODE=thorough

# Limit maximum subnets for safety
export MAX_SCAN_SUBNETS=100
```

### API Configuration
The scan behavior can be fine-tuned in the API configuration:

```python
# backend/app.py scan configuration
scan_config = {
    'scan_mode': 'thorough',  # or 'smart', 'full'
    'scanner_type': 'enhanced',  # for advanced features
    'aggressive': True,  # more thorough host detection
}
```

## Summary

The subnet scanning system is designed to intelligently handle networks of all sizes:

- Small networks (/24): Always fully scanned
- Medium networks (/20-/23): Comprehensively scanned by default
- Large networks (/16): Comprehensively scanned with 'thorough' mode
- Very large networks (/8-/15): Smart scanning with priority targeting

The key fix implemented ensures that /16 networks are properly scanned in their entirety when using 'thorough' or 'full' modes, addressing the issue where only the first /24 subnet was being scanned.