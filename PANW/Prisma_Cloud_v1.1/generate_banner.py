from PIL import Image, ImageDraw, ImageFont
import os

def generate_ascii_art():
    # ASCII Art for "Prisma2Cortex" and a Security Robot
    art = r"""
  ____       _                          _          
 |  _ \ _ __(_)___ _ __ ___   __ _  ___| |__   ___ 
 | |_) | '__| / __| '_ ` _ \ / _` |/ __| '_ \ / _ \
 |  __/| |  | \__ \ | | | | | (_| | (__| | | |  __/
 |_|   |_|  |_|___/_| |_| |_|\__,_|\___|_| |_|\___|
                                                   
             _   To   _
            (o)      (o)
   ____      |        |     ____           _            
  / ___|___  |________|    / ___|___  _ __| |_ _____  __
 | |   / _ \| '__| __|    | |   / _ \| '__| __/ _ \ \/ /
 | |__| (_) | |  | |_     | |__| (_) | |  | ||  __/>  < 
  \____\___/|_|   \__|     \____\___/|_|   \__\___/_/\_\
  
        [ Security Migration Bot ]
             _______
           _/       \_
          (   O   O   )
           \    _    /
           /`---'---'\
          /           \
         /  |   |   |  \
        *   |___|___|   *
            |_|   |_|
    """
    return art

def save_as_text(art, filename="tool_banner.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(art)
    print(f"ASCII art saved to {filename}")

def save_as_image(art, filename="tool_banner.jpg"):
    # Settings
    bg_color = (30, 30, 30) # Dark Gray
    text_color = (0, 255, 0) # Hacker Green
    font_size = 14
    
    # Try to load a monospace font
    try:
        # Windows default monospace font
        font = ImageFont.truetype("consola.ttf", font_size)
    except IOError:
        try:
            # Linux/Generic fallback
            font = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
        except IOError:
            # Default PIL font (might not align perfectly but works)
            font = ImageFont.load_default()

    # Calculate image size
    dummy_img = Image.new('RGB', (1, 1))
    draw = ImageDraw.Draw(dummy_img)
    bbox = draw.textbbox((0, 0), art, font=font)
    width = bbox[2] + 40  # Add padding
    height = bbox[3] + 40 # Add padding

    # Create image
    img = Image.new('RGB', (width, height), color=bg_color)
    draw = ImageDraw.Draw(img)
    
    # Draw text
    draw.text((20, 20), art, font=font, fill=text_color)
    
    # Save
    img.save(filename)
    print(f"JPEG banner saved to {filename}")

if __name__ == "__main__":
    art = generate_ascii_art()
    save_as_text(art)
    save_as_image(art)
