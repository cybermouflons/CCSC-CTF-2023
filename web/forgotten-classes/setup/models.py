from os import popen

class User: 
    def __init__(self, id, username, role) -> None:
        self.id = id
        self.username = username
        self.role = role

class Admin(User):
    def __init__(self, id, username):
        super().__init__(id, username, 'admin')

class Teacher(User):
    def __init__(self, id, username):
        super().__init__(id, username, 'teacher')

class Student(User):
    def __init__(self, id, username):
        super().__init__(id, username, 'student')

class Classroom:
    def get_max(self, students):
        return f"Max students: {students}\n"
    
class ComputerRoom(Classroom):
    def last_login(self):
        command = self.cmd if hasattr(self, 'cmd') else 'date'
        return f'Last login: {popen(command).read().strip()}'

class TechnologyRoom(Classroom):
    def get_items(self):
        return "There are 100 soldering irons left"

class Janitor(TechnologyRoom):
    def __init__(self, id, username) -> None:
        self.id = id
        self.username = username
        self.role = "janitor"