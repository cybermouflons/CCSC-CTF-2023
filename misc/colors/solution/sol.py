from PIL import Image

def get_box_colors(image_path):
    final_string=""
    image = Image.open(image_path)
    width, height = image.size
    box_size = 50

    # Check if the image dimensions are multiples of the box size
    if width % box_size != 0 or height % box_size != 0:
        print("Image dimensions are not compatible with the box size.")
        return

    for y in range(0, height, box_size):
        for x in range(0, width, box_size):
            box = (x, y, x + box_size, y + box_size)
            region = image.crop(box)
            color = region.getpixel((box_size // 2, box_size // 2))
            hex_value = '{:02x}{:02x}{:02x}'.format(*color)

            print(bytes.fromhex(hex_value).decode('utf-8'), end = '')

# Provide the path to your image file
image_path = '../public/COLORS.PNG'
get_box_colors(image_path)
