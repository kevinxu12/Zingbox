import argparse
import datetime
import filecmp
import os
import re
import shutil
import sys


class zingfamily:
    def __init__(self, old_dir=None, new_dir=None, list_excluded=None):
        self.current_dir = old_dir if old_dir is not None else os.getcwd() + "/plugins/"
        self.home_dir = new_dir if new_dir is not None else os.getcwd() + "/new_plugins/"
        self.list_excluded = list_excluded if list_excluded is not None else []
        self.list_family = ["Fedora Local Security Checks", "Web application abuses", "General",
                            "Windows:Microsoft Bulletins",
                            "Brute force attacks"]

    # iterates through all directories/subdirectories and updates the scripts
    def iterate(self):

        if self.current_dir.endswith("/"):
            root_dir = self.current_dir[:-1]
        else:
            root_dir = self.current_dir
        if self.home_dir.endswith("/"):
            new_root_dir = self.home_dir[:-1]
        else:
            new_root_dir = self.home_dir

        now = datetime.datetime.utcnow()
        time = str(now.month) + "-" + str(now.day) + "-" + str(now.year)
        log_name = time + "_change_log-1.txt"
        new_log_dir = new_root_dir + "/Logs"
        log = new_log_dir + "/" + log_name

        if not os.path.isdir(new_root_dir):
            os.mkdir(new_root_dir)
        if not os.path.isdir(new_log_dir):
            os.mkdir(new_log_dir)

        # dealing with the logs
        while os.path.exists(log):
            num = re.search(r'[0-9]+?(?=.txt)', log_name).group(0).encode('utf-8')
            new_num = str(int(num) + 1)
            log_name = log_name.replace("-" + num + ".txt", "-" + new_num + ".txt")
            log = new_log_dir + "/" + log_name

        logs = open(log, "w")

        # walk through directories
        for root, subdir, filename in os.walk(root_dir):
            var = root[len(root_dir):].replace("/", "", 1)
            structure = os.path.join(new_root_dir, var)
            if not os.path.isdir(structure):
                os.mkdir(structure)

            for f in filename:
                if not ".asc" in f:
                    new_filename = root.replace(root_dir, new_root_dir) + "/" + f
                    filename = root + "/" + f
                    if f not in self.list_excluded:
                        self.modifyFile(filename, new_filename, logs)
        self.remove(new_root_dir, root_dir, logs)

        logs.close()

    # add/modify/ new files into the existing folder. Modification works by creating a temporary file. If the temporary
    # file is the same as the existing file, the temporary file is deleted. Otherwise it overrides the existing file.
    def modifyFile(self, filename, new_filename, logs):

        if os.path.exists(new_filename):
            new_temp_filename = new_filename.replace(".", "_temp.")
            log = self.helper(new_temp_filename, filename, logs)
            isSame = self.isSame(new_temp_filename, new_filename)
            if isSame:
                os.remove(new_temp_filename)
                print "removing duplicate"
            else:
                shutil.move(new_temp_filename, new_filename)
                logs.write("Modified script: " + new_filename + "\n")
                logs.write("\n")

        else:
            log = self.helper(new_filename, filename, logs)
            logs.write("Added new script: " + new_filename + "\n")
            for element in log:
                if "ZB" in element:
                    logs.write("New family is: " + element)
                else:
                    logs.write("Old family was: " + element)
            logs.write("\n")

    # replace script family tag with zing box categorization
    def helper(self, new_filename, filename, logs):
        def doesContain(str, list):
            for element in list:
                if element in str:
                    return True
            return False

        list_log = []
        nasl_file = open(filename, 'r')
        new_nasl_file = open(new_filename, 'w')
        for line in nasl_file:
            find_family = re.search('script_family.+?(?=\);)', line)

            if find_family is not None:

                find_family = find_family.group(0)
                find_CVE = re.search('CVE-[0-9]{4}-[0-9]{4}', find_family)
                prefix = "  script_family("

                if find_CVE is not None:
                    uniq = "\"ZB-Family-Level-1\""
                elif doesContain(find_family, self.list_family):
                    uniq = "\"ZB-Family-Level-2\""
                else:
                    uniq = "\"ZB-Family-Level-3\""
                family_entry = prefix + uniq + ");\n"
                new_nasl_file.write("#" + line)
                list_log.append(line)
                list_log.append(family_entry)
                # logs.write("Original family for " + os.path.basename(filename) + " was:" + line)
                # logs.write("New family is:" + family_entry)
                # logs.write("\n")
                new_nasl_file.write(family_entry)
                # print "written"
            else:
                new_nasl_file.write(line)
        new_nasl_file.close()
        nasl_file.close()
        return list_log

    def main(self):
        self.iterate()

    # returns true if two files are the same ;false otherwise
    def isSame(self, new_temp_filename, new_filename):
        return filecmp.cmp(new_temp_filename, new_filename)

    # iterates through directory and removes files that are no longer there
    def remove(self, new_root_dir, root_dir, logs):
        for root, subdir, filename in os.walk(new_root_dir):
            for f in filename:
                old_root = root.replace(new_root_dir, root_dir)
                old_file_path = os.path.join(old_root, f)
                current_file_path = os.path.join(root, f)
                if not os.path.exists(old_file_path):
                     logs.write("Removed: " + root + "/" + f)
                     logs.write("\n No longer updated")
                     os.remove(current_file_path)


#  print new_nasl_file
def isReal(list_path):
    for path in list_path:
        if not os.path.isdir(path):
            print "not real path: " + path
            sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser("description=Extracts new scripts and customizes them for Zingbox")
    parser.add_argument("-f", dest="From", help="list out the absolute path of the plugins directory")
    parser.add_argument("-t", dest="To",
                        help="list out the absolute path where the new_plugins folder should be created")
    parser.add_argument("-e", dest="excluded", type=file, help="file containing names that should not be ignored")
    options = parser.parse_args()

    list_path = []
    old_dir = options.From
    new_dir = options.To
    list_path.append(old_dir)
    list_path.append(new_dir)
    file_excluded = options.excluded
    list_excluded = []
    if file_excluded is not None:
        for line in file_excluded:
            list_excluded.append(line)
    # list_path = list_path + list_excluded
    isReal(list_path)
    # print list_excluded
    # print new_dir
    # print old_dir
    bob = zingfamily(old_dir, new_dir, list_excluded)
    bob.main()

