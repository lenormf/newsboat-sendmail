#!/usr/bin/env python3
#
# newsboat-sendmail.py by lenormf
# A companion script that sends unread RSS items in Newsboat through email
#

import os
import sys
import fcntl
import shlex
import logging
import sqlite3
import pathlib
import datetime
import argparse
import subprocess
import configparser
import email.message

import bs4


class Defaults:
    FILENAME_CFG = "sendmail.cfg"

    CMD_SENDMAIL = "sendmail -F newsboat-sendmail -- {emails}"
    TMPL_SUBJECT = "[RSS][{rss_feed_title}] {rss_item_title}"
    CONTENT_TYPE = "html"
    TMPL_BODY = """<html>
<body>
<ul>
<li>Feed: {rss_feed_title}</li>
<li>Title: {rss_item_title}</li>
<li>Author: {rss_item_author}</li>
<li>Date: {rss_item_date}</li>
<li>Link: {rss_item_link}</li>
</ul>
<p>{rss_item_content_reflinks}</p>
</body>
</html>"""
    FMT_DATE = "%a %b %d %Y"


class NewsboatError(Exception): pass


class NewsboatSendmailConfig(configparser.ConfigParser):
    def __init__(self):
        super().__init__(interpolation=None)

        self["DEFAULT"]["sendmail_cmd"] = Defaults.CMD_SENDMAIL
        self["DEFAULT"]["emails"] = ""
        self["DEFAULT"]["subject_template"] = Defaults.TMPL_SUBJECT
        self["DEFAULT"]["content_type"] = Defaults.CONTENT_TYPE
        self["DEFAULT"]["body_template"] = Defaults.TMPL_BODY
        self["DEFAULT"]["date_format"] = Defaults.FMT_DATE

    def ReadFile(self, path):
        if path not in self.read(path):
            raise NewsboatError("unable to parse file: %s" % path)


class NewsboatConfig:
    def __init__(self, path):
        self._config = configparser.ConfigParser(
            delimiters=(' ', '\t'),
            comment_prefixes=('#'),
            converters={
                "qstring": NewsboatConfig.parse_qstring,
            },
        )

        try:
            with open(path, "r") as fin:
                data = fin.read()
        except OSError as e:
            raise NewsboatError("unable to open configuration file: %s" % e)

        try:
            self._config.read_string("[DEFAULT]\n%s" % data)
        except configparser.Error as e:
            raise NewsboatError("unable to parse configuration file: %s" % e)

    def __contains__(self, key):
        return self._config.has_option("DEFAULT", key)

    def __getitem__(self, key):
        raw_value = self._config["DEFAULT"][key]

        if raw_value.startswith('"'):
            return self._config["DEFAULT"].getqstring(key)
        else:
            return raw_value

    @staticmethod
    def parse_qstring(s):
        try:
            # XXX: shouldn't happen, but if it ever does, at least the script won't wait for data on stdin
            assert s is not None
            return shlex.split(s)[0]
        except ValueError:
            raise NewsboatError("unable to parse value: %s" % s)


class NewsboatBase:
    CMD_RELOAD = ["newsboat", "-x", "reload"]
    FILENAME_CACHE = "cache.db"

    def __init__(self, config):
        self.config = config

        home = os.getenv("HOME")
        xdg_config_home = os.getenv("XDG_CONFIG_HOME")
        xdg_data_home = os.getenv("XDG_DATA_HOME")

        self.dir_config = xdg_config_home or os.path.join(home, ".config")
        self.dir_data = xdg_data_home or os.path.join(home, ".local", "share")

        self.dir_config = os.path.join(self.dir_config, "newsboat")
        self.dir_data = os.path.join(self.dir_data, "newsboat")

        if not os.path.isdir(self.dir_config):
            logging.debug("the XDG configuration directory doesn't exit, rolling back to the HOME-based path")
            self.dir_config = os.path.join(home, ".newsboat")

        if not os.path.isdir(self.dir_data):
            logging.debug("the XDG data directory doesn't exit, rolling back to the HOME-based path")
            self.dir_data = os.path.join(home, ".newsboat")

        self.path_cache = os.path.join(self.dir_data, NewsboatBase.FILENAME_CACHE)

        path_newsboat_config = os.path.join(self.dir_config, "config")
        if os.path.isfile(path_newsboat_config):
            logging.info("loading the Newsboat configuration file")
            newsboat_config = NewsboatConfig(path_newsboat_config)
            if "cache-file" in newsboat_config:
                self.path_cache = newsboat_config["cache-file"]

        self.path_cache_lock = "%s.lock" % self.path_cache

        logging.debug("configuration directory: %s", self.dir_config)
        logging.debug("data directory: %s", self.dir_data)
        logging.debug("path to the cache: %s", self.path_cache)
        logging.debug("path to the cache lock file: %s", self.path_cache_lock)

    def LoadConfig(self, path=None):
        path_config = path or os.path.join(self.dir_config, Defaults.FILENAME_CFG)

        if os.path.isfile(path_config):
            logging.info("loading settings from file: %s", path_config)
            self.config.ReadFile(path_config)
        else:
            logging.info("no configuration file, ignoring")

    def Lock(self): pass
    def Unlock(self): pass
    def Update(self): pass

    def Sendmail(self, callback_sendmail_command):
        def flatten_string(s):
            return ' '.join(s.split('\n'))

        try:
            logging.info("connecting to the database")
            db = sqlite3.connect(self.path_cache)
            db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            raise NewsboatError("Unable to connect to the database: %s" % e)

        try:
            logging.info("iterating over all feeds")

            # FIXME: catch encoding errors
            for rss_feed in db.execute("SELECT * FROM `rss_feed`"):
                logging.info("iterating over all unread items in feed: %s", rss_feed["title"])

                if self.config.has_section(rss_feed["url"]):
                    logging.debug("loading settings from section with url: %s", rss_feed["url"])
                    feed_config = self.config[rss_feed["url"]]
                else:
                    logging.debug("loading defaults settings for the feed")
                    feed_config = self.config.defaults()

                if not feed_config["sendmail_cmd"]:
                    raise NewsboatError("no sendmail command set")
                elif feed_config["content_type"] not in ["html", "plain"]:
                    raise NewsboatError("invalid content type value")

                try:
                    emails = shlex.split(feed_config["emails"])
                    if not emails:
                        raise NewsboatError("no email addresses set")
                    emails = shlex.join(emails)
                except ValueError as e:
                    raise NewsboatError("unable to parse email addresses: %s" % e)

                try:
                    sendmail_command = shlex.split(feed_config["sendmail_cmd"].format(emails=emails))
                except ValueError as e:
                    raise NewsboatError("unable to parse the sendmail command: %s" % e)

                context_feed = {
                    "rss_feed_title": flatten_string(rss_feed["title"]),
                    "rss_feed_alias": flatten_string(feed_config.get("alias", "")),
                }

                rss_nb_items = db.execute("SELECT COUNT(*) FROM `rss_item` WHERE `unread` = 1 AND `feedurl` = ?", (rss_feed["rssurl"],)).fetchone()[0]

                logging.info("number of unread items in the feed: %d", rss_nb_items)

                idx_item = 0
                for rss_item in db.execute("SELECT * FROM `rss_item` WHERE `unread` = 1 AND `feedurl` = ? ORDER BY `pubDate` ASC", (rss_feed["rssurl"],)):
                    envelope = email.message.EmailMessage()
                    idx_item += 1

                    logging.info("handling item #%d", idx_item)

                    try:
                        rss_item_date = datetime.date.fromtimestamp(rss_item["pubDate"])
                    except OverflowError:
                        rss_item_date = datetime.date.today()
                    except OSError:
                        rss_item_date = datetime.date.fromtimestamp(0)

                    try:
                        rss_item_date = rss_item_date.strftime(feed_config["date_format"])
                    except ValueError as e:
                        raise NewsboatError("invalid time format: %s", e)

                    context_item = {
                        "rss_item_title": flatten_string(rss_item["title"]).strip(),
                        "rss_item_link": flatten_string(rss_item["url"]),
                        "rss_item_author": flatten_string(rss_item["author"]),
                        "rss_item_date": rss_item_date,
                        "rss_item_index": idx_item,
                        "rss_nb_items": rss_nb_items,
                    }

                    context_full = {**context_feed, **context_item}

                    subject = feed_config["subject_template"].format(**context_full).strip()
                    if not subject:
                        logging.warn("the email's subject is empty")
                    envelope["Subject"] = subject

                    content_type = feed_config["content_type"]
                    # TODO: class dedicated to handling a given content type
                    if content_type == "html":
                        try:
                            soup = bs4.BeautifulSoup(rss_item["content"], features="html.parser")
                        # NOTE: BeautifulSoup doesn't do any parsing, so exceptions are implementation dependent - we consider any to be a fatal error
                        except:
                            logging.error("unable to parse HTML, skipping")
                            continue

                        rss_item_content_astext = soup.get_text(strip=True)

                        links = []
                        for n, a in enumerate(soup.find_all("a")):
                            # Ignore links with no text
                            link_text = a.string.strip() if a.string is not None else ""
                            if not a.string:
                                continue

                            # Just flatten tags with no link
                            if "href" not in a.attrs:
                                a.replace_with(link_text)
                            else:
                                link = a["href"]
                                if link.startswith("#"):
                                    link = os.path.join(context_item["rss_item_link"], link)
                                links.append(link)
                                a.replace_with("{}[{}]".format(link_text, n))

                        if links:
                            ul = soup.new_tag("ul")
                            for n, link in enumerate(links):
                                li = soup.new_tag("li")
                                li.string = "[{}]: {}".format(n, link)
                                ul.insert(n, li)
                            soup.append(ul)

                        rss_item_content_reflinks = str(soup)
                    else:
                        rss_item_content_astext = rss_item["content"]
                        rss_item_content_reflinks = rss_item["content"]

                    # TODO: only pass HTML-related values when the content type is HTML?
                    contents = feed_config["body_template"].format(
                        **context_full,
                        rss_item_content=rss_item["content"],
                        rss_item_content_astext=rss_item_content_astext,
                        rss_item_content_reflinks=rss_item_content_reflinks,
                    )
                    if not contents:
                        logging.warn("the email's body is empty")
                    envelope.set_content(contents, subtype=content_type)

                    logging.debug("sendmail command: %s", sendmail_command)
                    logging.debug("email envelope: %s", envelope)

                    if callback_sendmail_command(sendmail_command, envelope):
                        try:
                            logging.info("marking item as read")
                            db.execute("UPDATE `rss_item` SET `unread` = 0 WHERE `id` = ?", (rss_item["id"],))
                            db.commit()
                        except sqlite3.Error as e:
                            raise NewsboatError("unable to mark item as read: %s" % e)

        except sqlite3.Error as e:
            raise NewsboatError("unable to read items: %s" % e)

        logging.info("closing the connection to the database")

        db.close()

    def ShowFeedLinks(self):
        try:
            logging.info("connecting to the database")
            db = sqlite3.connect(self.path_cache)
            db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            raise NewsboatError("Unable to connect to the database: %s" % e)

        try:
            logging.info("iterating over all feeds")

            for rss_feed in db.execute("SELECT `url` FROM `rss_feed`"):
                print(rss_feed["url"])

        except sqlite3.Error as e:
            raise NewsboatError("unable to read items: %s" % e)

        logging.info("closing the connection to the database")

        db.close()


class Newsboat(NewsboatBase):
    def __init__(self, config):
        super().__init__(config)

        self._lock_fd = None

    def Lock(self):
        p = pathlib.Path(self.path_cache_lock)

        logging.info("locking the database cache")

        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            raise NewsboatError("unable to create cache lock file: %s" % e)

        try:
            self._lock_fd = os.open(p, os.O_WRONLY | os.O_CREAT, mode=0o600)
            fcntl.lockf(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise NewsboatError("unable to acquire the lock-file, is Newsboat running? %s" % e)

        # NOTE: assume that getting a PID and writing to the lock-file will go as expected
        my_pid = "%d" % os.getpid()
        os.write(self._lock_fd, my_pid.encode())

    def Unlock(self):
        logging.info("unlocking the database cache")

        try:
            fcntl.lockf(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            os.unlink(self.path_cache_lock)
        except OSError as e:
            raise NewsboatError("unable to release the lock-file: %s" % e)

    def Update(self):
        logging.info("updating the database cache")

        try:
            subprocess.check_call(NewsboatBase.CMD_RELOAD)
        except (OSError, subprocess.CalledProcessError) as e:
            raise NewsboatError("Unable to update the database: %s" % e)

    def Sendmail(self):
        def callback_sendmail_command(sendmail_command, envelope):
            try:
                logging.info("sending email")

                p = subprocess.Popen(sendmail_command,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

                # FIXME: email might need to be flattened
                # https://github.com/rss2email/rss2email/blob/3654c9c15d2feffa331816c37f225f020fbb5474/rss2email/email.py#L257
                stdout, stderr = p.communicate(envelope.as_bytes())
                exit_code = p.wait()

                if stdout:
                    logging.debug("stdout: %s", stdout.decode("utf-8"))
                if stderr:
                    logging.debug("stderr: %s", stderr.decode("utf-8"))

                if exit_code:
                    raise NewsboatError("the sendmail command exited with error code: %d" % exit_code)
            except (OSError, subprocess.CalledProcessError) as e:
                raise NewsboatError("Unable to send email: %s" % e)

            return True

        super().Sendmail(callback_sendmail_command)


class NewsboatDryRun(NewsboatBase):
    def __init__(self, config):
        super().__init__(config)

    def Lock(self):
        print("write: %s" % self.path_cache_lock)

    def Unlock(self):
        print("unlink: %s" % self.path_cache_lock)

    def Update(self):
        print("exec: %s" % NewsboatBase.CMD_RELOAD)

    def Sendmail(self):
        def callback_sendmail_command(sendmail_command, envelope):
            print("exec: %s" % sendmail_command)
            return False

        super().Sendmail(callback_sendmail_command)


class CliOptions(argparse.Namespace):
    def __init__(self, args):
        parser = argparse.ArgumentParser(description="Newsboat Sendmail - A companion script that sends unread RSS items in Newsboat through email")

        parser.add_argument("-v", "--verbose", action="store_true", help="display information messages")
        parser.add_argument("-d", "--debug", action="store_true", help="display debug messages")
        parser.add_argument("-n", "--dry-run", action="store_true", help="do not modify the database, only print commands that would otherwise have been run")
        parser.add_argument("-u", "--update", action="store_true", help="update the database before sending the emails")
        parser.add_argument("-x", "--no-config", action="store_true", help="do not load any configuration file")
        parser.add_argument("-s", "--show-rss-links", action="store_true", help="display all feed links computed by Newsboat, and quit")
        parser.add_argument("-C", "--config", help="path to the configuration file")
        parser.add_argument("-S", "--sendmail-cmd", help="command using a sendmail-compatible tool to send emails")
        parser.add_argument("-E", "--emails", help="list of email addresses to send the feed items to, shell-quoted")
        parser.add_argument("-J", "--subject-template", help="template of the subject of outgoing emails")
        parser.add_argument("-T", "--content-type", choices=["html", "plain"], help="send plain text emails, or HTML ones")
        parser.add_argument("-B", "--body-template", help="template of the body of outgoing emails")

        parser.parse_args(args, self)


def main(av):
    cli_options = CliOptions(av[1:])
    exit_code = 0

    logging_level = logging.WARN
    if cli_options.debug:
        logging_level = logging.DEBUG
    elif cli_options.verbose:
        logging_level = logging.INFO
    logging.basicConfig(level=logging_level,
                        format="[%(asctime)s][%(levelname)s]: %(message)s")

    if cli_options.dry_run:
        logging.info("dry-run mode enabled, emails will not be sent, the database will not be modified, and the commands that would otherwise modify it will be printed")

    try:
        newsboat_sendmail_config = NewsboatSendmailConfig()
        newsboat = NewsboatDryRun(newsboat_sendmail_config) if cli_options.dry_run else Newsboat(newsboat_sendmail_config)

        if cli_options.show_rss_links:
            newsboat.ShowFeedLinks()
            return exit_code

        if not cli_options.no_config:
            newsboat.LoadConfig(cli_options.config)

        if cli_options.sendmail_cmd:
            newsboat_sendmail_config["DEFAULT"]["sendmail_cmd"] = cli_options.sendmail_cmd
        if cli_options.emails:
            newsboat_sendmail_config["DEFAULT"]["emails"] = cli_options.emails
        if cli_options.subject_template:
            newsboat_sendmail_config["DEFAULT"]["subject_template"] = cli_options.subject_template
        if cli_options.body_template:
            newsboat_sendmail_config["DEFAULT"]["body_template"] = cli_options.body_template

        if cli_options.update:
            newsboat.Update()

        newsboat.Lock()

        try:
            newsboat.Sendmail()
        except NewsboatError as e:
            logging.error("%s", e)
            exit_code = 2
        except KeyboardInterrupt:
            logging.info("process interrupted, quitting")

        newsboat.Unlock()

    except NewsboatError as e:
        logging.error("%s", e)
        exit_code = 1
    except KeyboardInterrupt:
        logging.info("process interrupted, quitting")

    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
