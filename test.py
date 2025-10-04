import json
def process_json_file(file_path):
    """
    Reads a JSON file and processes its data.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            print(json.dumps(data, indent=4)) #pretty print json.
            # Example of processing data:
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"{key}: {value}")
    except FileNotFoundError:
        print(f"Error: JSON file '{file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{file_path}'.")
    except Exception as e:
        print(f"An error occurred: {e}")
# Example Usage:
# process_json_file("sample.json")
