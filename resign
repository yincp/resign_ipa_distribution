#!/usr/bin/env python
#
# Resigning a IPA file use specified Distribution provision. This tool
# only work on Mac OSX on which iOS development tools are installed.
#
# Copyright (c) 2015 by Yincp (yincp@126.com). All rights reserved.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#---------------------------------------------------------------------



from pprint import pprint
import sys
import os
import datetime
import tempfile
import shutil
import re
import zipfile
import plistlib
import optparse
import json
import shutil
import subprocess

DEFAULT_ENCODING = 'utf-8'
VERSION_NUMBER = '1.0'



def do_resign(ipa_file, provision_file, dest_file):
    # check whether Distribution mobileprovision
    provision_xml_rx = re.compile(r'<\?xml.+</plist>', re.DOTALL)
    provision_fh = open(provision_file, 'rb')
    content = provision_fh.read()
    match = provision_xml_rx.search(content)
    if (match is not None):
        provision_xml_content = match.group()
        provision_data = plistlib.readPlistFromString(provision_xml_content)
        provision_fh.close()
    else:
        print_and_close(-9007, 'unable to parse specified .mobileprovision file')
    if 'ProvisionsAllDevices' not in provision_data or not provision_data['ProvisionsAllDevices']:
        print_and_close(-9008, 'specified file is not a Distribution mobileprofile')
    # check expiration
    if ('ExpirationDate' in provision_data):
        expire_date = provision_data['ExpirationDate']
        difference_date = expire_date - datetime.datetime.today()
        days_until_expire = difference_date.days + 1
        if days_until_expire <= 0:
            print_and_close(-9009, 'mobileprovision is expired')

    # check teamname certification is installed and get signature
    result_lines = os.popen('security find-identity -vv -p codesigning').readlines()
    regx = re.compile(r'^\s*\d+\)\s(\w{40})\s"iPhone Distribution: %s"[\r\n]*$' % provision_data['TeamName'])
    signature = ''
    for line in result_lines:
        m = regx.match(line)
        if m is not None:
            signature = m.group(1)
            break
    if signature == '':
        print_and_close(-9010, 'certification file which maths the mobileprovision is not installed')

    # make or clear work path
    work_path = '/tmp/resign'
    try:
        if os.path.exists(work_path):
            if os.path.isfile(work_path):
                os.remove(work_path)
            elif os.path.isdir(work_path):
                shutil.rmtree(work_path)
        os.makedirs(work_path)
    except Exception, e:
        print_and_close(-9011, 'make dir failed: %s' % e.message)

    # generate xcent file using bundleid and teamid in provision
    teamid = provision_data['TeamIdentifier'][0]
    bundleid = provision_data['Entitlements']['application-identifier']
    bundleid = re.sub(r'%s\.' % teamid, '', bundleid)
    xcent_xml_body = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>%s.%s</string>
	<key>com.apple.developer.team-identifier</key>
	<string>%s</string>
	<key>get-task-allow</key>
	<false/>
	<key>keychain-access-groups</key>
	<array>
		<string>%s.%s</string>
	</array>
</dict>
</plist>
'''
    xcent_xml_body = xcent_xml_body % (teamid, bundleid, teamid, teamid, bundleid)
    xcent_fd = os.path.join(work_path, '%s.xcent' % bundleid)
    try:
        if os.path.exists(xcent_fd):
            os.remove(xcent_fd)
        xcent_fh = open(xcent_fd, 'w')
        xcent_fh.write(xcent_xml_body)
        xcent_fh.flush()
        xcent_fh.close()
    except Exception, e:
        print_and_close(-9012, 'write xcent file failed: %s' % e.message)

    # unzip ipa
    os.chdir(work_path)
    zip_path = os.path.join(work_path, 'zipfile')
    cmd = ''
    try:
        os.makedirs(zip_path)
        # cmd = 'unzip %s -d %s' % (ipa_file, zip_path)
        # os.popen(cmd).readlines()
        zip_obj = zipfile.ZipFile(ipa_file, 'r')
        for name in zip_obj.namelist():
            sub_path_name = os.path.dirname(name)
            desc_path_name = os.path.join(zip_path, sub_path_name)
            desc_name = os.path.join(zip_path, name)
            if not os.path.exists(desc_path_name):
                os.makedirs(desc_path_name)
            data = zip_obj.read(name)
            if not os.path.exists(desc_name):
                fo = open(desc_name, 'w')
                fo.write(data)
                fo.close()
        zip_obj.close()
    except Exception, e:
        print_and_close(-9013, 'unzip ipa failed: %s' % e.message)
    # check if Payload is not found
    subs = os.listdir(zip_path)
    if 'Payload' not in subs:
        os.chdir(zip_path)
        if 'payload' in subs:
            cmd = 'mv payload Payload'
            os.popen(cmd).readlines()
        elif 'Applications' in subs:
            cmd = 'mv Applications Payload'
            os.popen(cmd).readlines()
        else:
            print_and_close(-9014, 'cant find Payload in ipa')
    os.chdir(work_path)
    # get to xx.app directory
    ipa_app_path = os.path.join(zip_path, 'Payload')
    subs = os.listdir(ipa_app_path)
    regx = re.compile(r'.*\.app$', re.I)
    ipa_app_name = ''
    for sub in subs:
        if regx.match(sub):
            ipa_app_name = sub
            break
    if ipa_app_name == '':
        print_and_close(-9015, 'cant find .app in Payload')
    ipa_app_path = os.path.join(ipa_app_path, ipa_app_name)

    # check whether the executable is signed with a distribution profile
    # try:
    #     cmd = 'codesign -vv -d "%s"' % ipa_app_path
    #     result_lines = execute_cmd(cmd)
    #     regx = re.compile(r'^Authority=iPhone Distribution: (.*)[\r\n]*$')
    #     for line in result_lines:
    #         m = regx.match(line)
    #         if m is not None:
    #             print_and_close(-9022, 'the executable is signed with a distribution profile: %s' % m.group(1))
    # except Exception, e:
    #     pass


    # also resign the dylibs and frameworks in .app/Frameworks/ directory
    try:
        swift_lib_in_app = os.path.join(ipa_app_path, 'Frameworks')
        if os.path.exists(swift_lib_in_app) and os.path.isdir(swift_lib_in_app):
            dylibs = os.listdir(swift_lib_in_app)
            regx = re.compile(r'.*?\.(dylib|framework)', re.I)
            for dylib in dylibs:
                if regx.match(dylib):
                    dylib_path = os.path.join(swift_lib_in_app, dylib)
                    cmd = 'codesign --force --sign %s --entitlements "%s" "%s"' % (signature, xcent_fd, dylib_path)
                    execute_cmd(cmd)
    except:
        pass

    # also resign appexs in .app/Plugins directory
    try:
        plugin_in_app = os.path.join(ipa_app_path, 'Plugins')
        if os.path.exists(plugin_in_app) and os.path.isdir(plugin_in_app):
            plugins = os.listdir(plugin_in_app)
            regx = re.compile(r'.*?\.appex', re.I)
            for plugin_name in plugins:
                if regx.match(plugin_name):
                    plugin_path = os.path.join(plugin_in_app, plugin_name)
                    resign_app_path(plugin_path, bundleid, provision_file, signature, xcent_fd, 'appex')

                    # check whether there is a app directory -- for watch kit app
                    try:
                        subs_in_plugin_path = os.listdir(plugin_path)
                        regx2 = re.compile(r'.*?\.app', re.I)
                        for sub_in_plugin in subs_in_plugin_path:
                            if regx2.match(sub_in_plugin):
                                wkapp_path = os.path.join(plugin_path, sub_in_plugin)
                                resign_app_path(wkapp_path, bundleid, provision_file, signature, xcent_fd, 'wkapp')
                    except Exception, e2:
                        print_and_close(-9024, 'codesign watchkit app failed: %s' % e2.message)

    except Exception, e:
        print_and_close(-9023, 'codesign plugin failed: %s' % e.message)

    # resign the main app
    resign_app_path(ipa_app_path, bundleid, provision_file, signature, xcent_fd, 'app')


    # zip to a ipa
    try:
        os.chdir(zip_path)
        cmd = 'zip -r %s *' % dest_file
        os.popen(cmd).readlines()
    except Exception, e:
        print_and_close(-9021, 'generate resigned.ipa failed: %s' % e.message)

    print_and_close(0, 'resigned success and save ipa to %s' % dest_file)
# end do_resign

def resign_app_path(app_path, app_bundle_id, provision_file, sign_signature, xcent_file, app_type):
    bundle_id = app_bundle_id
    if app_type == 'appex':
        bundle_id = '%s.appex' % bundle_id
    elif app_type == 'wkapp':
        bundle_id = '%s.wkapp' % bundle_id

    # modify bundleid in Info.plist
    try:
        plist_fd = os.path.join(app_path, 'Info.plist')
        if not os.path.exists(plist_fd):
            print_and_close(-9016, 'cant find Info.plist')
        cmd = 'plutil -replace CFBundleIdentifier -string %s "%s"' % (bundle_id, plist_fd)
        os.popen(cmd).readlines()

        if app_type == 'wkapp':
            cmd = 'plutil -replace WKCompanionAppBundleIdentifier -string %s "%s"' % (app_bundle_id, plist_fd)
            os.popen(cmd).readlines()
        elif app_type == 'appex':
            plist_data = read_plist(plist_fd)
            appex_whether_wkappex = False
            if plist_data is not None:
                if plist_data.has_key('NSExtension'):
                    plist_extension = plist_data['NSExtension']
                    if plist_extension is not None and plist_extension.has_key('NSExtensionPointIdentifier'):
                        extension_type = plist_extension['NSExtensionPointIdentifier']
                        if extension_type == 'com.apple.watchkit':
                            appex_whether_wkappex = True
            if appex_whether_wkappex:
                cmd = 'plutil -replace NSExtension.NSExtensionAttributes.WKAppBundleIdentifier -string %s.wkapp "%s"' % (app_bundle_id, plist_fd)
                os.popen(cmd).readlines()

    except Exception, e:
        print_and_close(-9017, 'plutil failed: %s' % e.message)


    # remove _CodeSignature directory
    try:
        sig_file_path = os.path.join(app_path, '_CodeSignature')
        if os.path.exists(sig_file_path):
            if os.path.isdir(sig_file_path):
                shutil.rmtree(sig_file_path)
            else:
                os.remove(sig_file_path)
    except Exception, e:
        print_and_close(-9018, 'remove _CodeSignature failed: %s' % e.message)

    # remove embedded.mobileprovision and copy our mobileprovision
    try:
        embedded_provision_fd = os.path.join(app_path, 'embedded.mobileprovision')
        if os.path.exists(embedded_provision_fd):
            os.remove(embedded_provision_fd)
        shutil.copy(provision_file, embedded_provision_fd)
    except Exception, e:
        print_and_close(-9019, 'copy embedded.mobileprovision failed: %s' % e.message)

    # resign
    try:
        cmd = 'codesign --force --sign %s --entitlements "%s" "%s"' % (sign_signature, xcent_file, app_path)
        execute_cmd(cmd)
    except Exception, e:
        print_and_close(-9020, 'codesign failed: %s' % e.message)
# end resign_app_path

def execute_cmd(cmd):
    result_lines = []
    try:
        cmd_process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        result_lines.extend(cmd_process.stdout.readlines())
        result_lines.extend(cmd_process.stderr.readlines())
        cmd_process.kill()   #need to kill?
    except:
        pass
    return result_lines

def read_plist(plist_file):
    try:
        f = open(plist_file, 'r')
        content = f.read(1024)
        f.close()
        xml_rx = re.compile(r'<\??xml')
        if xml_rx.match(content):
            return plistlib.readPlistFromString(content)
        else:
            new_xml_plist = '%s.xml' % os.path.basename(plist_file)
            new_xml_plist = os.path.join('/tmp/resign', new_xml_plist)
            if os.path.exists(new_xml_plist):
                os.remove(new_xml_plist)
            shutil.copy(plist_file, new_xml_plist)
            cmd = 'plutil -convert xml1 "%s"' % new_xml_plist
            os.system(cmd)
            return plistlib.readPlist(new_xml_plist)
    except:
        pass

    return None
# end read_plist


class MyJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.__str__()
        if isinstance(obj, plistlib.Data):
            return '<Data>' #obj.__repr__()
        return json.JSONEncoder.default(self, obj)
# end MyJsonEncoder class

class MyOptionParser(optparse.OptionParser):
    def format_epilog(self, formatter):
        return self.epilog
# end MyOptionParser class

def get_options():

    error_in_output = '''
Error numbers in json formatted output as follow:
    -9001	ipa file not found
    -9002	ipa file is not a zip file
    -9003	mobileprovision file not found
    -9004	command 'security' not found!
    -9005	command 'codesign' not found!
    -9006   command 'plutil' not found!
    -9007   unable to parse specified .mobileprovision file
    -9008   specified file is not a Distribution mobileprofile
    -9009   mobileprovision is expired
    -9010   certification file which maths the mobileprovision is not installed
    -9011   make dir failed
    -9012   write xcent file failed
    -9013   unzip ipa failed
    -9014   cant find Payload in ipa
    -9015   cant find .app in Payload
    -9016   cant find Info.plist
    -9017   plutil failed
    -9018   remove _CodeSignature failed
    -9019   copy embedded.mobileprovision failed
    -9020   codesign failed
    -9021   generate resigned.ipa failed
    -9022   the executable is signed with a distribution profile
    -9023   codesign plugin failed
    -9024   codesign watchkit app failed
'''

    version_info = 'resign: version %s' % (VERSION_NUMBER)
    optp = MyOptionParser(version=version_info, epilog=error_in_output)

    optp.add_option('-i', '--ipafile', action='store', dest='ipa_file',
                    help='Specified IPA filename')
    optp.add_option('-p', '--provision', action='store', dest='provision_file',
                    help='Specified mobileprovision filename')
    optp.add_option('-d', '--destination', action='store', dest='dest_file',
                    help='Specified filenae which resigned ipa is saved. If not set, the resigned ipa will be saved as xxx-resigend.ipa in original directory')

    optp.set_usage('checkipa -i <ipa filename> -p <provision filename>]')

    opts_args = optp.parse_args()
    return opts_args[0]
# end get_options


def print_and_close(code, message):
    print json.dumps({'code': code, 'message': message}, cls=MyJsonEncoder, indent=4)
    try:
        shutil.rmtree('/tmp/resign')
    except:
        pass
    exit( 0 if code == 0 else -1 )
# end print_and_close


def main():

    # get command line arguments
    options = get_options()
    ipa_file = os.path.abspath(options.ipa_file)
    provision_file = os.path.abspath(options.provision_file)
    dest_file = options.dest_file

    errors = []

    if ipa_file is None or not os.path.exists(ipa_file):
        print_and_close(-9001, 'ipa file not found')

    if not zipfile.is_zipfile(ipa_file):
        print_and_close(-9002, 'ipa file is not a zip file')

    if provision_file is None or not os.path.exists(provision_file):
        print_and_close(-9003, 'mobileprovision not found')


    # check whether security and codesign is installed.
    retval = os.system('which security >/dev/null')
    if retval != 0:
        print_and_close(-9004, "command 'security' not found!")
    # check whether security is installed.
    retval = os.system('which codesign >/dev/null')
    if retval != 0:
        print_and_close(-9005, "command 'codesign' not found!")
    # check whether security is installed.
    retval = os.system('which plutil >/dev/null')
    if retval != 0:
        print_and_close(-9006, "command 'plutil' not found!")

    # save as xxx-resigned.ipa if dest_file is not specified
    if dest_file is None or dest_file == '':
        orig_path = os.path.dirname(ipa_file)
        orig_name = os.path.basename(ipa_file)
        regx = re.compile(r'(.*)(\.[a-zA-Z0-9]{2,16})$', re.I)
        m = regx.match(orig_name)
        if m is not None:
            new_filename = '%s-resigned.ipa' % m.group(1)
        else:
            new_filename = '%s%s' % (orig_name, '-resigned.ipa')
        dest_file = os.path.join(orig_path, new_filename)
    else:
        dest_file = os.path.abspath(dest_file)



    do_resign(ipa_file, provision_file, dest_file)

# end main()

if __name__ == '__main__':
    main()
    sys.exit(0)
