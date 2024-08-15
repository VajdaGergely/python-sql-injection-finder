import os, json

def create_folders():
    folders = [
        "output",
        "output/1_lines_with_sql_keywords",
        "output/2_is_commented_out",
        "output/2_is_commented_out/commented_out",
        "output/2_is_commented_out/not_commented_out",
        "output/3_is_vulnerable",
        "output/3_is_vulnerable/vulnerable",
        "output/3_is_vulnerable/not_vulnerable"
    ]
    for folder in folders:
        os.makedirs(folder, exist_ok=True)

def write_results(tested_source_file, scanner):
    # all matches in json format
    with open("output/all_matches_json_formatted.txt", "w") as f0:
            f0.write(json.dumps(scanner.matches))

    # sql matches
    if len(scanner.matches["sql"]) > 0:
        f1 = open("output/1_lines_with_sql_keywords/1_plain.txt", "w")
        f2 = open("output/1_lines_with_sql_keywords/2_numbered.txt", "w")
        for match in scanner.matches["sql"]:
            line_text = scanner.get_full_line_text(match["start"], match["end"]) + '\n'
            f1.write(line_text)
            f2.write(tested_source_file + ":" + str(scanner.lines.search_no(match["end"])) + ":" + line_text)
        f1.close()
        f2.close()
        
        with open("output/1_lines_with_sql_keywords/3_json_formatted.txt", "w") as f3:
            f3.write(json.dumps(scanner.matches))

    # commented - uncommented
    if len(scanner.matches["commented"]) > 0:
        pass
    if len(scanner.matches["uncommented"]) > 0:
        pass
    if len(scanner.matches["safe"]) > 0:
        pass
    if len(scanner.matches["vulnerable"]) > 0:
        pass