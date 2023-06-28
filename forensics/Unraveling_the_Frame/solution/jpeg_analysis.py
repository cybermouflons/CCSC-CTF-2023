# def find_sof_segment(file_path):
#     with open(file_path, 'rb') as file:
#         jpeg_data = file.read()

#     # Search for the Start of Frame (SOF) marker
#     sof_marker = b'\xff\xc0'
#     sof_index = jpeg_data.find(sof_marker)

#     if sof_index != -1:
#         # Extract the segment data
#         segment_data = jpeg_data[sof_index : sof_index + 19]

#         # Print the Start of Frame (SOF) segment
#         print("Found Start of Frame (SOF) segment:")
#         print("Segment Data:", ' '.join([f"{byte:02X}" for byte in segment_data]))


# # Usage
# image_path = "The_flag_is_flying_at_an_impressive_height.jpg"
# find_sof_segment(image_path)



def find_sof_segment(file_path):
    with open(file_path, 'rb') as file:
        jpeg_data = file.read()

    # Search for the Start of Frame (SOF) marker
    sof_marker = b'\xff\xc0'
    sof_index = jpeg_data.find(sof_marker)

    if sof_index != -1:
        # Extract the segment data
        segment_data = jpeg_data[sof_index : sof_index + 19]

        return segment_data

    return None

def break_down_sof_segment(segment_data):
    marker = segment_data[:2]
    length = segment_data[2:4]
    bits_per_pixel = segment_data[4]
    image_height = segment_data[5:7]
    image_width = segment_data[7:9]
    num_components = segment_data[9]

    component_data = segment_data[10:]
    components = []
    for i in range(num_components):
        component_index = component_data[i * 3]
        sampling_factor = component_data[i * 3 + 1]
        quant_table_number = component_data[i * 3 + 2]
        components.append((component_index, sampling_factor, quant_table_number))

    return marker, length, bits_per_pixel, image_height, image_width, num_components, components

# Usage
image_path = "Unraveling the Frame: Seeking the Start of Flag (SOF).jpg"

segment_data = find_sof_segment(image_path)
if segment_data:
    marker, length, bits_per_pixel, image_height, image_width, num_components, components = break_down_sof_segment(segment_data)

    # Print the breakdown of the SOF segment
    print("SOF (start of frame) segment:")
    print("Marker:", marker.hex())
    print("Length:", length.hex())
    print("Bits per Pixel:", bits_per_pixel)
    print("Image Height:", image_height.hex())
    print("Image Width:", image_width.hex())
    print("Number of Components:", num_components)

    for component in components:
        component_index, sampling_factor, quant_table_number = component
        print("Component:", component_index)
        print("Sampling Factor:", sampling_factor)
        print("Quantization Table Number:", quant_table_number)
else:
    print("Start of Frame (SOF) segment not found in the image.")
