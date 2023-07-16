import os
import yaml
import sys

def generate_challenge_list(directory):
    challenge_table = "| Name | Author |\n| ---- | ------ |\n"
    with open(os.path.join(directory, "challenge.yml"), "r") as file:
        challenge = yaml.load(file, Loader=yaml.FullLoader)
        challenge_table += f"| [{challenge['name']}]({directory}) | {challenge['author']} |\n"
    return challenge_table

def main():
    directories = sys.argv[1]
    print("Directories:", directories)

    challenge_categories = {}
    for directory in directories:
        category_table = generate_challenge_list(directory)
        challenge_categories[directory] = category_table

    readme_template = ""
    with open("README.md", "r") as file:
        readme_template = file.read()

    challenges_section = ""
    for category, table in challenge_categories.items():
        challenges_section += f"### {category}\n\n{table}\n\n"

    readme_content = readme_template.replace("{{ challenges_placeholder }}", challenges_section.strip())

    with open("README.md", "w") as file:
        file.write(readme_content)

if __name__ == "__main__":
    main()