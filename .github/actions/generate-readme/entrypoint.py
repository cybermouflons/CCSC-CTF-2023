import os
import yaml
import sys
from jinja2 import Environment, FileSystemLoader


class IgnoreSpecificConstructorLoader(yaml.SafeLoader):
    def ignore_constructor(self, node):
        return None


IgnoreSpecificConstructorLoader.add_constructor(
    "!filecontents", IgnoreSpecificConstructorLoader.ignore_constructor
)


def parse_challenge(directory):
    path = os.path.join(directory, "challenge.yml")
    print(path)
    with open(path, "r") as file:
        return yaml.load(file, Loader=IgnoreSpecificConstructorLoader)


def main():
    directories = sys.argv[1].split(" ")
    challenge_categories = {}

    for directory in directories:
        challenge = parse_challenge(directory)
        category = challenge["category"]
        if category not in challenge_categories:
            challenge_categories[category] = []
        challenge_categories[category].append(challenge)

    file_loader = FileSystemLoader("/")
    env = Environment(loader=file_loader)
    template = env.get_template("README.jinja")

    output = template.render(challenge_categories=challenge_categories)

    with open("README.md", "w") as file:
        file.write(output)


if __name__ == "__main__":
    main()
