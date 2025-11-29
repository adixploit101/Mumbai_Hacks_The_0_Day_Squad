# Logo Upload Instructions

## Adding Your Custom Logo

The Security Platform supports custom logos in the dashboard and PDF reports.

### Supported Formats
- PNG (recommended)
- JPG/JPEG
- SVG

### Recommended Specifications
- **Size**: 512x512 pixels (square)
- **Format**: PNG with transparent background
- **File size**: < 500KB
- **Color**: Works best with light/white logo on dark background

### Installation Steps

1. **Prepare your logo file**
   - Name it `logo.png` (or `logo.jpg`, `logo.svg`)
   - Ensure it's square or has transparent padding

2. **Place in project directory**
   ```bash
   # Copy your logo to the project root
   copy C:\path\to\your\logo.png F:\Mumbai_AI_Agents\logo.png
   ```

3. **Verify placement**
   ```
   F:\Mumbai_AI_Agents\
   ├── logo.png          ← Your logo here
   ├── dashboard.html
   ├── api.py
   └── ...
   ```

4. **Restart the application**
   ```bash
   # Stop the API if running (Ctrl+C)
   # Start again
   python api.py
   ```

5. **Verify logo appears**
   - Open dashboard: http://localhost:8000
   - Check sidebar (top-left corner)
   - Generate PDF report to see logo in reports

### Multiple Logo Sizes (Optional)

For best quality across all uses, you can provide multiple sizes:

```
F:\Mumbai_AI_Agents\
├── logo.png           # Main logo (512x512)
├── logo_small.png     # Sidebar logo (64x64)
├── logo_report.png    # Report header (200x200)
```

Then update the code references:
- Dashboard sidebar: `logo_small.png`
- PDF reports: `logo_report.png`

### Troubleshooting

**Logo not showing in dashboard:**
- Clear browser cache (Ctrl+F5)
- Check browser console for errors
- Verify file path is correct
- Ensure file permissions allow reading

**Logo not showing in PDF:**
- Check `logo.png` exists in project root
- Verify file format is supported
- Try converting to PNG if using other format
- Check `report_generator.py` logo_path parameter

**Logo looks distorted:**
- Use square dimensions (1:1 aspect ratio)
- Add transparent padding if needed
- Increase resolution (minimum 256x256)

### Example Logo Preparation

Using any image editor (Photoshop, GIMP, Paint.NET):

1. Open your logo
2. Resize to 512x512 pixels
3. Add transparent background if needed
4. Export as PNG
5. Save as `logo.png`

### Default Fallback

If no logo is provided, the system will use:
- Dashboard: Shield icon (🛡️)
- PDF Reports: Text-based header

This ensures the platform works even without a custom logo.
