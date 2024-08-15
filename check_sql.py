import json, re

class Lines:
    def __init__(self, data):
        self.data = data
        self.lines = []     # [ {"start" : X, "end" : Y, "text" : "ZZZ"} ... {...} ]
        start_pos = 0
        i = 0
        while i < len(self.data):
            if self.data[i] == "\n":
                self.lines.append({
                    "start" : start_pos,
                    "end" : i,
                })
                start_pos = i + 1
            i += 1

    def __getitem__(self, index):
        return { **self.lines[index], "text" : self.data[self.lines[index]["start"]:self.lines[index]["end"]] }

    def __len__(self):
        return len(self.lines)

    def search(self, pos):
        i = 0
        while i < len(self.lines):
            if pos <= self.lines[i]["end"]:
                return { **self.lines[i], "text" : self.data[self.lines[i]["start"]:self.lines[i]["end"]] }
            i += 1
        return None

    def search_no(self, pos):
        i = 0
        while i < len(self.lines):
            if pos <= self.lines[i]["end"]:
                return i
            i += 1
        return -1

    def __str__(self):
        result = []
        for line in self.lines:
            result.append({ "start" : line["start"], "end" : line["end"], "text" : self.data[line["start"]:line["end"]] })
        return json.dumps(result)
    
    def dump(self):
        result = []
        for line in self.lines:
            result.append({ "start" : line["start"], "end" : line["end"], "text" : self.data[line["start"]:line["end"]] })
        return json.dumps(result, indent=4)



class SqlScanner:
    def __init__(self, data, lines):
        self.data = data
        self.lines = lines
        self.matches = {
            "sql" : [],
            "commented" : [],
            "uncommented" : [],
            "safe" : [],
            "vulnerable" : []
        }

    def get_full_line_text(self, search_start_pos, search_end_pos):
        # searching line start
        line_start = -1
        i = search_start_pos
        while True:
            if self.data[i] == '\n':
                line_start = i + 1      # line_stat -> first char right after \n
                break
            elif i == 0:
                line_start = i
                break
            i -= 1
        
        # searching line end
        line_end = -1
        i = search_end_pos
        while True:
            if self.data[i] == '\n' or i == len(self.data)-1:      # line_end -> \n that had been found
                line_end = i
                break
            i += 1

        # return line
        return self.data[line_start:line_end]

    #collecting matches from 'data' class field (which is the whole vba string)
    def scan_sql_code(self):
        regex = r"(\b(SELECT|UPDATE)\b)|(\b(INSERT INTO|DELETE FROM|EXEC )\b)|(\b(CREATE DATABASE|DROP DATABASE|BACKUP DATABASE|TO DISK|CREATE TABLE|ALTER TABLE|DROP TABLE|TRUNCATE TABLE|CREATE INDEX|CREATE UNIQUE INDEX|CREATE VIEW|CREATE OR REPLACE VIEW|CREATE PROCEDURE|ALTER COLUMN|ADD CONSTRAINT|PRIMARY KEY|FOREIGN KEY|DROP COLUMN|DROP CONSTRAINT|DROP INDEX|DROP PRIMARY KEY|DROP FOREIGN KEY|DROP CHECK|DROP DEFAULT|DROP VIEW)\b)"

        for match in re.finditer(regex, self.data, re.IGNORECASE):
            self.matches["sql"].append({
                "start" : match.start(),
                "end" : match.end(),
                "text" : match.group()
            })

    #working based on the preliminary collected sql matches
    #get whole lines by lines[], and check if sql part is commented or not
    def scan_commented_code(self):
        #regex cannot to be used to count quotes so we don't know if comment character is in a string or not
        #code is used instead of regex
        
        # iterating through 'sql' matches
        i = 0
        while i < len(self.matches["sql"]):
            end_pos = self.matches["sql"][i]["start"]
            start_pos = self.data.rfind('\n', 0, end_pos)+1 # search for last \n and put start_pos to the char right after

            # searching for single quotes that are not enclosed in double quotes (a comment sign that is not within string...)
            commented = False
            within_string = False
            j = start_pos
            while j < end_pos:
                if self.data[j] == "'" and not within_string:
                    commented = True
                    break
                elif self.data[j] == '"':
                    within_string = not within_string
                j += 1

            #saving results
            if commented:
                self.matches["commented"].append(self.matches["sql"][i])
            else:
                self.matches["uncommented"].append(self.matches["sql"][i])
            
            #go to next line
            i += 1

    #working based on the uncommented sql matches
    #searching for regex matches
    def scan_vulnerable_code(self):
        # searching for '&' and '"' characters with arbitrary whitespaces between
        regex = '&\s*\"|\"\s*&'
        i = 0
        while i < len(self.matches["uncommented"]):
            #get line text
            pos = self.matches["sql"][i]["start"] #get the start pos of the sqli keyword
            line_text = self.lines.search(pos)["text"] #get text of full line that contains the sqli keyword

            #regex search in line text
            result = re.search(regex, line_text, re.IGNORECASE)
            if result == None:
                self.matches["vulnerable"].append(self.matches["uncommented"][i])
            else:
                self.matches["safe"].append(self.matches["uncommented"][i])
            i += 1

    def __str__(self):
        return json.dumps(self.matches)
    
    def dump(self):
        return json.dumps(self.matches, indent=4)