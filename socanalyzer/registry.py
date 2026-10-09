from socanalyzer import parser, webparser

# log type name -> function with the signature parse_file(path, year)
PARSERS = {
    "auth": parser.parse_file,
    "web": webparser.parse_file,
}

PARSE_LINES = {
    "auth": parser.parse_line,
    "web": webparser.parse_line,
}