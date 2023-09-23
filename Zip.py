import zipfile
import shutil


def zip(dir_in="", archived_filename="", format="zip"):
    """Archive the directory into a ZIP file in the current directory

    Args:
        dir (str, optional): The current directory. Defaults to "".
        filename (str, optional): The archived file name. Defaults to "".
        format (str, optional): the archive format. Defaults to "zip".
    """
    shutil.make_archive(base_name=archived_filename,
                        format=format, root_dir=dir_in)


def unzip(archived_filename="", dir_out=""):
    """Extract the archived file into a directory

    Args:
        archived_filename (str, optional): The archived file. Defaults to "".
        dir_out (str, optional): The directory to save extracted files. Defaults to "".
    """
    shutil.unpack_archive(filename=archived_filename, extract_dir=dir_out)
