import math
from PIL import Image, ImageDraw, ImageFilter

def create_shield_logo(size=1024, dark_bg=False):
    # RGBA image
    bg_color = (15, 23, 42, 255) if dark_bg else (0, 0, 0, 0)
    img = Image.new("RGBA", (size, size), bg_color)
    
    # Scale coordinates relative to 1024
    scale = size / 1024.0
    
    # Shield polygon points (high precision curve approximation)
    points = []
    
    # Top center
    cx, cy = 512, 100
    
    # Top curved rim from (512, 110) to right shoulder (860, 200)
    for t in range(0, 31):
        angle = t / 30.0
        x = 512 + 348 * math.sin(angle * math.pi / 2)
        y = 110 + 90 * (1 - math.cos(angle * math.pi / 2))
        points.append((x * scale, y * scale))
        
    # Right side down to right hip (850, 520)
    for t in range(0, 21):
        p = t / 20.0
        x = 860 - 10 * p
        y = 200 + 320 * p
        points.append((x * scale, y * scale))
        
    # Right hip down to bottom tip (512, 920)
    for t in range(0, 51):
        p = t / 50.0
        # Smooth bezier curve
        x = (1-p)**2 * 850 + 2*(1-p)*p * 750 + p**2 * 512
        y = (1-p)**2 * 520 + 2*(1-p)*p * 780 + p**2 * 920
        points.append((x * scale, y * scale))
        
    # Left curve from bottom tip (512, 920) to left hip (174, 520)
    for t in range(0, 51):
        p = t / 50.0
        x = (1-p)**2 * 512 + 2*(1-p)*p * 274 + p**2 * 174
        y = (1-p)**2 * 920 + 2*(1-p)*p * 780 + p**2 * 520
        points.append((x * scale, y * scale))
        
    # Left hip up to left shoulder (164, 200)
    for t in range(0, 21):
        p = t / 20.0
        x = 174 - 10 * p
        y = 520 - 320 * p
        points.append((x * scale, y * scale))
        
    # Left shoulder to top center (512, 110)
    for t in range(0, 31):
        angle = t / 30.0
        x = 164 + 348 * (1 - math.cos(angle * math.pi / 2))
        y = 200 - 90 * math.sin(angle * math.pi / 2)
        points.append((x * scale, y * scale))

    # Glow layer
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.polygon(points, fill=(0, 150, 255, 180))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=25 * scale))
    img.paste(glow, (0, 0), glow)

    # Base shield gradient fill
    shield_mask = Image.new("L", (size, size), 0)
    mask_draw = ImageDraw.Draw(shield_mask)
    mask_draw.polygon(points, fill=255)
    
    # Create gradient
    grad = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    grad_draw = ImageDraw.Draw(grad)
    for y in range(size):
        ratio = y / size
        # Vibrant Royal Blue to Deep Cobalt
        r = int(0 * (1-ratio) + 20 * ratio)
        g = int(120 * (1-ratio) + 60 * ratio)
        b = int(255 * (1-ratio) + 210 * ratio)
        grad_draw.line([(0, y), (size, y)], fill=(r, g, b, 255))
        
    img.paste(grad, (0, 0), shield_mask)

    # Outer Shield Rim Stroke (Cyan glow)
    rim_draw = ImageDraw.Draw(img)
    rim_draw.line(points + [points[0]], fill=(56, 189, 248, 255), width=int(14 * scale), joint="curve")
    
    # Inner bevel line
    inner_points = [((p[0] - 512*scale) * 0.94 + 512*scale, (p[1] - 515*scale) * 0.94 + 515*scale) for p in points]
    rim_draw.line(inner_points + [inner_points[0]], fill=(147, 197, 253, 140), width=int(5 * scale), joint="curve")

    # Center Pure White Bold 'Z' Glyph
    # Coords designed for 1024x1024
    z_points = [
        (330 * scale, 360 * scale),   # Top Left
        (694 * scale, 360 * scale),   # Top Right
        (694 * scale, 450 * scale),   # Top Right down
        (474 * scale, 640 * scale),   # Diagonal down-left
        (694 * scale, 640 * scale),   # Bottom Right pre-corner
        (694 * scale, 730 * scale),   # Bottom Right
        (330 * scale, 730 * scale),   # Bottom Left
        (330 * scale, 640 * scale),   # Bottom Left up
        (550 * scale, 450 * scale),   # Diagonal up-right
        (330 * scale, 450 * scale),   # Top Left cut
    ]
    
    # Drop shadow behind 'Z'
    z_shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    z_shadow_draw = ImageDraw.Draw(z_shadow)
    z_shadow_draw.polygon([(x + 4*scale, y + 8*scale) for x, y in z_points], fill=(15, 23, 42, 160))
    z_shadow = z_shadow.filter(ImageFilter.GaussianBlur(radius=8 * scale))
    img.paste(z_shadow, (0, 0), z_shadow)
    
    # Draw White 'Z'
    draw = ImageDraw.Draw(img)
    draw.polygon(z_points, fill=(255, 255, 255, 255))
    
    return img

if __name__ == "__main__":
    import os
    
    out_dir = r"c:\Users\DELL\OneDrive\Desktop\analysis testing\tester\frontend\public"
    brain_dir = r"C:\Users\DELL\.gemini\antigravity\brain\a3f6067a-f37e-4352-b520-b9d9880c683a"
    
    # 1024x1024 transparent
    img_1024 = create_shield_logo(1024, dark_bg=False)
    p1 = os.path.join(out_dir, "zylorun-shield-logo.png")
    img_1024.save(p1, "PNG")
    print(f"Saved: {p1}")
    
    # Copy to brain dir for embedding
    p1_brain = os.path.join(brain_dir, "zylorun-shield-logo.png")
    img_1024.save(p1_brain, "PNG")
    print(f"Saved: {p1_brain}")
    
    # 512x512
    img_512 = create_shield_logo(512, dark_bg=False)
    p2 = os.path.join(out_dir, "zylorun-shield-logo-512.png")
    img_512.save(p2, "PNG")
    print(f"Saved: {p2}")
    
    # 1024x1024 on dark background
    img_dark = create_shield_logo(1024, dark_bg=True)
    p3 = os.path.join(out_dir, "zylorun-shield-logo-dark.png")
    img_dark.save(p3, "PNG")
    print(f"Saved: {p3}")
    
    # Copy to root desktop analysis testing folder as well
    p_root = r"c:\Users\DELL\OneDrive\Desktop\analysis testing\zylorun-shield-logo.png"
    img_1024.save(p_root, "PNG")
    print(f"Saved: {p_root}")
