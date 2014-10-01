#!/bin/env python

"""
The MIT License

Copyright (c) 2010 The Chicago Tribune & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from multiprocessing import Pool
import os
import re
import socket
import time
import urllib2
import base64
import csv
import sys
import random

import boto
import boto.ec2
import paramiko
import copy
import datetime

STATE_FILENAME = os.path.expanduser('~/.bees')

# Utilities


def _read_server_list():
    instance_ids = []

    if not os.path.isfile(STATE_FILENAME):
        return (None, None, None, None)

    with open(STATE_FILENAME, 'r') as f:
        username = f.readline().strip()
        key_name = f.readline().strip()
        zone = f.readline().strip()
        text = f.read()
        instance_ids = [i for i in text.split('\n') if i.strip()]

        print 'Read %i bees from the roster.' % len(instance_ids)

    return (username, key_name, zone, instance_ids)


def _write_server_list(username, key_name, zone, instances):
    with open(STATE_FILENAME, 'w') as f:
        f.write('%s\n' % username)
        f.write('%s\n' % key_name)
        f.write('%s\n' % zone)
        f.write('\n'.join([instance.id for instance in instances]))


def _delete_server_list():
    os.remove(STATE_FILENAME)


def _get_pem_path(key):
    key = os.path.expanduser('~/.ssh/%s.pem' % key)
    print "using ", key
    return key


def _get_region(zone):
    # chop off the "d" in the "us-east-1d" to get the "Region"
    return zone if 'gov' in zone else zone[:-1]


def _get_security_group_ids(connection, security_group_names, subnet):
    ids = []
    # Since we cannot get security groups in a vpc by name, we get all
    # security groups and parse them by name later
    security_groups = connection.get_all_security_groups()

    # Parse the name of each security group and add the id of any match to the
    # group list
    for group in security_groups:
        for name in security_group_names:
            if group.name == name:
                if subnet is None:
                    if group.vpc_id is None:
                        ids.append(group.id)
                    elif group.vpc_id is not None:
                        ids.append(group.id)

        return ids

# Methods


def _wait_for_fulfillment(conn, request_ids):
    """Loop through all pending request ids waiting for them to be fulfilled.
    If a request is fulfilled, remove it from pending_request_ids.
    If there are still pending requests, sleep and check again in 10 seconds.
    Only return when all spot requests have been fulfilled."""
    pending_request_ids = copy.deepcopy(request_ids)

    while pending_request_ids:
        results = conn.get_all_spot_instance_requests(
            filters={'status-code': 'fulfilled'},
            request_ids=pending_request_ids)
        for result in results:
            pending_request_ids.pop(pending_request_ids.index(result.id))
            print "spot request `{}` fulfilled!".format(result.id)

        time.sleep(10)
    print "all spots fulfilled!"


def _create_spot_instance(count, group, zone, image_id, instance_type,
                          username, key_name, subnet, max_spot_bid):
    region_name = _get_region(zone)

    ec2_connection = boto.ec2.connect_to_region(region_name)

    requests = ec2_connection.get_all_spot_instance_requests(
        filters={'launch_group': 'beeswithmachineguns',
                 'state': ['active', 'open']})

    if requests:
        request_ids = [r.id for r in requests]
        _wait_for_fulfillment(ec2_connection, request_ids)

        fulfilled = ec2_connection.get_all_spot_instance_requests(
            filters={'launch_group': 'beeswithmachineguns',
                     'status-code': 'fulfilled'})

        reservations = ec2_connection.get_all_instances(
            instance_ids=[f.instance_id for f in fulfilled])

        return [i for r in reservations for i in r.instances]

    groups = [group] if subnet is None else _get_security_group_ids(
        ec2_connection, [group], subnet)

    req = ec2_connection.request_spot_instances(
        count=count,
        price=max_spot_bid,
        instance_type=instance_type,
        image_id=image_id,
        launch_group="beeswithmachineguns",
        availability_zone_group=region_name,
        key_name=key_name,
        security_groups=groups,
        placement=None if 'gov' in zone else zone,
        subnet_id=subnet
    )

    print "wait for requests to be accepted"
    time.sleep(10)

    ec2_connection.get_all_spot_instance_requests(
        request_ids=[r.id for r in req],
        filters={'launch_group': 'beeswithmachineguns',
                 'status-code': ['fulfilled', 'open']})

    _wait_for_fulfillment(ec2_connection, [r.id for r in req])

    fulfilled = ec2_connection.get_all_spot_instance_requests(
        filters={'launch_group': 'beeswithmachineguns',
                 'status-code': 'fulfilled'})

    reservations = ec2_connection.get_all_instances(
        instance_ids=[f.instance_id for f in fulfilled])

    return [i for r in reservations for i in r.instances]


def up(count, group, zone, image_id, instance_type, username, key_name, subnet, bid):
    """
    Startup the load testing server.
    """

    existing_username, existing_key_name, existing_zone, instance_ids = _read_server_list(
    )

    if instance_ids:
        print 'Bees are already assembled and awaiting orders.'
        return

    count = int(count)

    pem_path = _get_pem_path(key_name)

    if not os.path.isfile(pem_path):
        print 'Warning. No key file found for %s. You will need to add this key to your SSH agent to connect.' % pem_path

    print 'Connecting to the hive.'

    ec2_connection = boto.ec2.connect_to_region(_get_region(zone))

    print 'Attempting to call up %i bees.' % count

    if bid:
        instances = _create_spot_instance(
            count, group, zone, image_id, instance_type,
            username, key_name, subnet, bid)
    else:
        reservation = ec2_connection.run_instances(
            image_id=image_id,
            min_count=count,
            max_count=count,
            key_name=key_name,
            security_groups=[group] if subnet is None else _get_security_group_ids(
                ec2_connection, [group], subnet),
            instance_type=instance_type,
            placement=None if 'gov' in zone else zone,
            subnet_id=subnet)
        instances = reservation.instances

    print 'Waiting for bees to load their machine guns...'

    instance_ids = []

    for instance in instances:
        instance.update()
        while instance.state != 'running':
            print '.'
            time.sleep(5)
            instance.update()

        instance_ids.append(instance.id)

        print 'Bee %s is ready for the attack.' % instance.id

    ec2_connection.create_tags(instance_ids, {"Name": "a bee!"})

    _write_server_list(username, key_name, zone, instances)

    print 'The swarm has assembled %i bees.' % len(instances)


def report():
    """
    Report the status of the load testing servers.
    """
    username, key_name, zone, instance_ids = _read_server_list()

    if not instance_ids:
        print 'No bees have been mobilized.'
        return

    ec2_connection = boto.ec2.connect_to_region(_get_region(zone))

    reservations = ec2_connection.get_all_instances(instance_ids=instance_ids)

    instances = []

    for reservation in reservations:
        instances.extend(reservation.instances)

    for instance in instances:
        print 'Bee %s: %s @ %s' % (instance.id, instance.state, instance.ip_address)


def down():
    """
    Shutdown the load testing server.
    """
    username, key_name, zone, instance_ids = _read_server_list()

    if not instance_ids:
        print 'No bees have been mobilized.'
        return

    print 'Connecting to the hive.'

    ec2_connection = boto.ec2.connect_to_region(_get_region(zone))

    print 'Calling off the swarm.'

    terminated_instance_ids = ec2_connection.terminate_instances(
        instance_ids=instance_ids)

    print 'Stood down %i bees.' % len(terminated_instance_ids)

    _delete_server_list()


def _install_vegeta(client):
    # install
    channel = client.invoke_shell()
    stdin = channel.makefile('wb')
    stdout = channel.makefile('rb')

    stdin.write(b'sudo yum install -y docker\r')
    stdin.write(b'sudo service docker start\r')
    stdin.write(
        b'curl https://raw.githubusercontent.com/Mistobaan/beeswithmachineguns/feature/spot-instances/Dockerfile > Dockerfile\r')
    stdin.write(b'sudo docker build -t beeswithmachineguns/client:latest .\r')
    stdin.write(b'sudo yum install -y httpd-tools\rexit\r')

    stdin.write(b'exit\r')

    print stdout.read()


import json


def _run_vegeta(client, params, options):
    response = {}
    channel = client.invoke_shell()
    stdin = channel.makefile('wb')
    stdout = channel.makefile('rb')
    print "Running Vegeta "
    cmd = b'sudo docker run -v /tmp:/tmp -w /tmp --rm beeswithmachineguns/client:latest attack -rate=2000 -duration=1m -targets=/tmp/targets -output=result.bin \r'
    print cmd
    stdin.write(cmd)
    cmd = b'sudo docker run -v /tmp:/tmp -w /tmp --rm beeswithmachineguns/client:latest report -input=/tmp/result.bin -reporter=json -output=/tmp/output.json \r'
    print cmd
    stdin.write(cmd)

    stdin.write(b'exit\r')

    print stdout.read()
    print "vegeta done"
    stdin, stdout, stderr = client.exec_command(
        'cat /tmp/output.json' % params)
    response['result'] = json.loads(stdout.read())
    print response['result']
    return response

import subprocess


def _upload(params, source, destination):
    print "Uploading ", source, " to ", destination
    pem_file_path = _get_pem_path(params['key_name'])
    cmd = [
        "scp", "-q", "-o", "StrictHostKeyChecking=no", "-i", pem_file_path, source, "%s@%s:%s" % (params['username'],
                                                                                                  params[
                                                                                                  'instance_name'],
                                                                                                  destination)]
    print cmd
    subprocess.check_output(cmd)
    print "upload done"


def _run_ab(client, params, options):
    stdin, stdout, stderr = client.exec_command('mktemp')
    params['csv_filename'] = stdout.read().strip()
    if params['csv_filename']:
        options += ' -e %(csv_filename)s' % params
    else:
        print 'Bee %i lost sight of the target (connection timed out creating csv_filename).' % params['i']
        return None

    if params['post_file']:
        pem_file_path = _get_pem_path(params['key_name'])
        _upload(params, pem_file_path, "/tmp/honeycomb")
        pem_file_path = _get_pem_path(params['key_name'])
        os.system(
            "scp -q -o 'StrictHostKeyChecking=no' -i %s %s %s@%s:/tmp/honeycomb" %
            (pem_file_path, params['post_file'], params['username'], params['instance_name']))
        options += ' -T "%(mime_type)s; charset=UTF-8" -p /tmp/honeycomb' % params

    if params['keep_alive']:
        options += ' -k'

    if params['cookies'] is not '':
        options += ' -H \"Cookie: %ssessionid=NotARealSessionID;\"' % params[
            'cookies']
    else:
        options += ' -C \"sessionid=NotARealSessionID\"'

    if params['basic_auth'] is not '':
        options += ' -A %s' % params['basic_auth']

    params['options'] = options
    benchmark_command = 'ab -r -n %(num_requests)s -c %(concurrent_requests)s %(options)s "%(url)s"' % params
    stdin, stdout, stderr = client.exec_command(benchmark_command)

    response = {}

    ab_results = stdout.read()
    ms_per_request_search = re.search(
        'Time\ per\ request:\s+([0-9.]+)\ \[ms\]\ \(mean\)', ab_results)

    if not ms_per_request_search:
        print 'Bee %i lost sight of the target (connection timed out running ab).' % params['i']
        return None

    requests_per_second_search = re.search(
        'Requests\ per\ second:\s+([0-9.]+)\ \[#\/sec\]\ \(mean\)', ab_results)
    failed_requests = re.search(
        'Failed\ requests:\s+([0-9.]+)', ab_results)
    complete_requests_search = re.search(
        'Complete\ requests:\s+([0-9]+)', ab_results)

    response['ms_per_request'] = float(ms_per_request_search.group(1))
    response['requests_per_second'] = float(
        requests_per_second_search.group(1))
    response['failed_requests'] = float(failed_requests.group(1))
    response['complete_requests'] = float(
        complete_requests_search.group(1))

    stdin, stdout, stderr = client.exec_command(
        'cat %(csv_filename)s' % params)
    response['request_time_cdf'] = []
    for row in csv.DictReader(stdout):
        row["Time in ms"] = float(row["Time in ms"])
        response['request_time_cdf'].append(row)
    if not response['request_time_cdf']:
        print 'Bee %i lost sight of the target (connection timed out reading csv).' % params['i']
        return None

    print 'Bee %i is out of ammo.' % params['i']


from itertools import izip_longest


def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return izip_longest(fillvalue=fillvalue, *args)


import os
import tempfile
import math


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def _split(filename, n):
    chunks = []

    lines = file_len(filename)

    lines_per_file = int(math.ceil(lines / float(n)))

    print "Diving test file in %d parts each with %d requests " % (lines, n)

    with open(filename) as f:
        for i, g in enumerate(grouper(lines_per_file, f, fillvalue=None)):
            with tempfile.NamedTemporaryFile('w', delete=False) as fout:
                # count number of lines in group
                for j, line in enumerate(g, 1):
                    if line is None:
                        j -= 1  # don't count this line
                        break
                    fout.write(line)
            #result = 'small_file_{0}'.format(i * n + j)
            print fout.name
            chunks.append(fout.name)
    return chunks


def _install_ab(client):
    channel = client.invoke_shell()
    stdin = channel.makefile('wb')
    stdout = channel.makefile('rb')
    stdin.write(b'sudo yum install -y httpd-tools\rexit\r')
    print stdout.read()


def _attack(params):
    """
    Test the target URL with requests.

    Intended for use with multiprocessing.
    """
    print 'Bee %i is joining the swarm.' % params['i']

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pem_path = params.get('key_name') and _get_pem_path(
            params['key_name']) or None
        if not os.path.isfile(pem_path):
            client.load_system_host_keys()
            client.connect(
                params['instance_name'], username=params['username'])
        else:
            client.connect(
                params['instance_name'],
                username=params['username'],
                key_filename=pem_path)

        print 'Bee %i is firing her machine gun. Bang bang!' % params['i']

        options = ''
        if params['headers'] is not '':
            for h in params['headers'].split(';'):
                if h != '':
                    options += ' -H "%s"' % h.strip()

        if False:
            _install_ab(client)
            response = _run_ab(client, params, options)
        else:
            _install_vegeta(client)
            _upload(params, params["target_file"], "/tmp/targets")
            response = _run_vegeta(client, params, options)
        client.close()
        return response
    except socket.error, e:
        import traceback
        traceback.print_exc()
        return e


def _summarize_results(results, params, csv_filename):
    summarized_results = dict()
    summarized_results['timeout_bees'] = [r for r in results if r is None]
    summarized_results['exception_bees'] = [
        r for r in results if type(r) == socket.error]
    summarized_results['complete_bees'] = [
        r for r in results if r is not None and type(r) != socket.error]
    summarized_results['timeout_bees_params'] = [
        p for r, p in zip(results, params) if r is None]
    summarized_results['exception_bees_params'] = [
        p for r, p in zip(results, params) if type(r) == socket.error]
    summarized_results['complete_bees_params'] = [
        p for r, p in zip(results, params) if r is not None and type(r) != socket.error]
    summarized_results['num_timeout_bees'] = len(
        summarized_results['timeout_bees'])
    summarized_results['num_exception_bees'] = len(
        summarized_results['exception_bees'])
    summarized_results['num_complete_bees'] = len(
        summarized_results['complete_bees'])

    complete_results = [r['complete_requests']
                        for r in summarized_results['complete_bees']]
    summarized_results['total_complete_requests'] = sum(complete_results)

    complete_results = [r['failed_requests']
                        for r in summarized_results['complete_bees']]
    summarized_results['total_failed_requests'] = sum(complete_results)

    complete_results = [r['requests_per_second']
                        for r in summarized_results['complete_bees']]
    summarized_results['mean_requests'] = sum(complete_results)

    complete_results = [r['ms_per_request']
                        for r in summarized_results['complete_bees']]
    summarized_results['mean_response'] = sum(
        complete_results) / summarized_results['num_complete_bees']

    summarized_results['tpr_bounds'] = params[0]['tpr']
    summarized_results['rps_bounds'] = params[0]['rps']

    if summarized_results['tpr_bounds'] is not None:
        if summarized_results['mean_response'] < summarized_results['tpr_bounds']:
            summarized_results['performance_accepted'] = True
        else:
            summarized_results['performance_accepted'] = False

    if summarized_results['rps_bounds'] is not None:
        if summarized_results['mean_requests'] > summarized_results['rps_bounds'] and summarized_results['performance_accepted'] is True or None:
            summarized_results['performance_accepted'] = True
        else:
            summarized_results['performance_accepted'] = False

    summarized_results['request_time_cdf'] = _get_request_time_cdf(
        summarized_results['total_complete_requests'], summarized_results['complete_bees'])
    if csv_filename:
        _create_request_time_cdf_csv(results, summarized_results[
                                     'complete_bees_params'], summarized_results['request_time_cdf'], csv_filename)

    return summarized_results


def _create_request_time_cdf_csv(results, complete_bees_params, request_time_cdf, csv_filename):
    if csv_filename:
        with open(csv_filename, 'w') as stream:
            writer = csv.writer(stream)
            header = ["% faster than", "all bees [ms]"]
            for p in complete_bees_params:
                header.append("bee %(instance_id)s [ms]" % p)
            writer.writerow(header)
            for i in range(100):
                row = [i, request_time_cdf[i]]
                for r in results:
                    row.append(r['request_time_cdf'][i]["Time in ms"])
                writer.writerow(row)


def _get_request_time_cdf(total_complete_requests, complete_bees):
    # Recalculate the global cdf based on the csv files collected from
    # ab. Can do this by sampling the request_time_cdfs for each of
    # the completed bees in proportion to the number of
    # complete_requests they have
    n_final_sample = 100
    sample_size = 100 * n_final_sample
    n_per_bee = [int(r['complete_requests'] / total_complete_requests * sample_size)
                 for r in complete_bees]
    sample_response_times = []
    for n, r in zip(n_per_bee, complete_bees):
        cdf = r['request_time_cdf']
        for i in range(n):
            j = int(random.random() * len(cdf))
            sample_response_times.append(cdf[j]["Time in ms"])
    sample_response_times.sort()
    request_time_cdf = sample_response_times[
        0:sample_size:sample_size / n_final_sample]

    return request_time_cdf


def _print_results(summarized_results):
    """
    Print summarized load-testing results.
    """
    if summarized_results['exception_bees']:
        print '     %i of your bees didn\'t make it to the action. They might be taking a little longer than normal to find their machine guns, or may have been terminated without using "bees down".' % summarized_results['num_exception_bees']

    if summarized_results['timeout_bees']:
        print '     Target timed out without fully responding to %i bees.' % summarized_results['num_timeout_bees']

    if summarized_results['num_complete_bees'] == 0:
        print '     No bees completed the mission. Apparently your bees are peace-loving hippies.'
        return

    print '     Complete requests:\t\t%i' % summarized_results['total_complete_requests']

    print '     Failed requests:\t\t%i' % summarized_results['total_failed_requests']

    print '     Requests per second:\t%f [#/sec] (mean of bees)' % summarized_results['mean_requests']
    if 'rps_bounds' in summarized_results and summarized_results['rps_bounds'] is not None:
        print '     Requests per second:\t%f [#/sec] (upper bounds)' % summarized_results['rps_bounds']

    print '     Time per request:\t\t%f [ms] (mean of bees)' % summarized_results['mean_response']
    if 'tpr_bounds' in summarized_results and summarized_results['tpr_bounds'] is not None:
        print '     Time per request:\t\t%f [ms] (lower bounds)' % summarized_results['tpr_bounds']

    print '     50%% responses faster than:\t%f [ms]' % summarized_results['request_time_cdf'][49]
    print '     90%% responses faster than:\t%f [ms]' % summarized_results['request_time_cdf'][89]

    if 'performance_accepted' in summarized_results:
        print '     Performance check:\t\t%s' % summarized_results['performance_accepted']

    if summarized_results['mean_response'] < 500:
        print 'Mission Assessment: Target crushed bee offensive.'
    elif summarized_results['mean_response'] < 1000:
        print 'Mission Assessment: Target successfully fended off the swarm.'
    elif summarized_results['mean_response'] < 1500:
        print 'Mission Assessment: Target wounded, but operational.'
    elif summarized_results['mean_response'] < 2000:
        print 'Mission Assessment: Target severely compromised.'
    else:
        print 'Mission Assessment: Swarm annihilated target.'


def attack(url, n, c, **options):
    """
    Test the root url of this site.
    """
    username, key_name, zone, instance_ids = _read_server_list()
    headers = options.get('headers', '')
    csv_filename = options.get("csv_filename", '')
    cookies = options.get('cookies', '')
    post_file = options.get('post_file', '')
    keep_alive = options.get('keep_alive', False)
    basic_auth = options.get('basic_auth', '')

    if csv_filename:
        try:
            stream = open(csv_filename, 'w')
        except IOError, e:
            raise IOError(
                "Specified csv_filename='%s' is not writable. Check permissions or specify a different filename and try again." % csv_filename)

    if not instance_ids:
        print 'No bees are ready to attack.'
        return

    print 'Connecting to the hive.'

    ec2_connection = boto.ec2.connect_to_region(_get_region(zone))

    print 'Assembling bees.'

    reservations = ec2_connection.get_all_instances(instance_ids=instance_ids)

    instances = []

    for reservation in reservations:
        instances.extend(reservation.instances)

    instance_count = len(instances)

    if n < instance_count * 2:
        print 'bees: error: the total number of requests must be at least %d (2x num. instances)' % (instance_count * 2)
        return
    if c < instance_count:
        print 'bees: error: the number of concurrent requests must be at least %d (num. instances)' % instance_count
        return
    if n < c:
        print 'bees: error: the number of concurrent requests (%d) must be at most the same as number of requests (%d)' % (c, n)
        return

    requests_per_instance = int(float(n) / instance_count)
    connections_per_instance = int(float(c) / instance_count)

    print 'Each of %i bees will fire %s rounds, %s at a time.' % (instance_count, requests_per_instance, connections_per_instance)

    params = []

    chunks = _split("./targets_all", len(instances))

    for i, instance in enumerate(instances):
        params.append({
            'target_file': chunks[i],
            'i': i,
            'instance_id': instance.id,
            'instance_name': instance.public_dns_name,
            'url': url,
            'concurrent_requests': connections_per_instance,
            'num_requests': requests_per_instance,
            'username': username,
            'key_name': key_name,
            'headers': headers,
            'cookies': cookies,
            'post_file': options.get('post_file'),
            'keep_alive': options.get('keep_alive'),
            'mime_type': options.get('mime_type', ''),
            'tpr': options.get('tpr'),
            'rps': options.get('rps'),
            'basic_auth': options.get('basic_auth')
        })

    print 'Stinging URL so it will be cached for the attack.'

    request = urllib2.Request(url)
    # Need to revisit to support all http verbs.
    if post_file:
        try:
            with open(post_file, 'r') as content_file:
                content = content_file.read()
            request.add_data(content)
        except IOError:
            print 'bees: error: The post file you provided doesn\'t exist.'
            return

    if cookies is not '':
        request.add_header('Cookie', cookies)

    if basic_auth is not '':
        authentication = base64.encodestring(basic_auth).replace('\n', '')
        request.add_header('Authorization', 'Basic %s' % authentication)

    # Ping url so it will be cached for testing
    dict_headers = {}
    if headers is not '':
        dict_headers = headers = dict(j.split(':')
                                      for j in [i.strip()
                                                for i in headers.split(';')
                                                if i != ''
                                                ])

    for key, value in dict_headers.iteritems():
        request.add_header(key, value)

    response = urllib2.urlopen(request)
    response.read()

    print 'Organizing the swarm.'

    # Spin up processes for connecting to EC2 instances
    debug = False
    if not debug:
        pool = Pool(len(params))
        results = pool.map(_attack, params)
    else:
        results = []
        for p in params:
            print "Bee %s" % p["instance_name"]
            results.append(_attack(p))
            print "Bee %s DONE" % p["instance_name"]

    summarized_results = _summarize_results(results, params, csv_filename)
    print 'Offensive complete.'
    _print_results(summarized_results)

    print 'The swarm is awaiting new orders.'

    if 'performance_accepted' in summarized_results:
        if summarized_results['performance_accepted'] is False:
            print("Your targets performance tests did not meet our standard.")
            sys.exit(1)
        else:
            print(
                'Your targets performance tests meet our standards, the Queen sends her regards.')
            sys.exit(0)

# spot history code is inspired by starcluster
# https://github.com/jtriley/StarCluster
import iso8601
import calendar


def iso_to_datetime_tuple(iso):
    """
    Converts an iso time string to a datetime tuple
    """
    return iso8601.parse_date(iso)


def _iso_to_unix_time(iso):
    dtup = iso_to_datetime_tuple(iso)
    secs = calendar.timegm(dtup.timetuple())
    return secs


def _iso_to_javascript_timestamp(iso):
    """
    Convert dates to Javascript timestamps (number of milliseconds since
    January 1st 1970 UTC)
    """
    secs = _iso_to_unix_time(iso)
    return secs * 1000


def _is_iso_time(iso):
    """
    Returns True if provided time can be parsed in iso format
    to a datetime tuple
    """
    try:
        iso_to_datetime_tuple(iso)
        return True
    except iso8601.ParseError:
        return False


def _datetime_tuple_to_iso(tup):
    """
    Converts a datetime tuple to a UTC iso time string
    """
    iso = datetime.datetime.strftime(tup.astimezone(iso8601.iso8601.UTC),
                                     "%Y-%m-%dT%H:%M:%S.%fZ")
    return iso


def _get_utc_now(iso=False):
    """
    Returns datetime.utcnow with UTC timezone info
    """
    now = datetime.datetime.utcnow().replace(tzinfo=iso8601.iso8601.UTC)
    if iso:
        return _datetime_tuple_to_iso(now)
    else:
        return now


def spot_price(instance_type, zone=None, classic=False, vpc=False):
    if classic and vpc:
        raise BaseException(
            "classic and vpc kwargs are mutually exclusive")
    if not classic and not vpc:
        classic = not vpc
    if classic:
        pdesc = "Linux/UNIX"
        short_pdesc = "EC2-Classic"
    else:
        pdesc = "Linux/UNIX (Amazon VPC)"
        short_pdesc = "VPC"
    print ("Fetching spot history for %s (%s)" %
          (instance_type, short_pdesc))

    days_ago = 1
    end_tup = _get_utc_now()

    start = _datetime_tuple_to_iso(
        end_tup - datetime.timedelta(days=days_ago))
    end = _datetime_tuple_to_iso(end_tup)

    region_name = _get_region(zone)

    conn = boto.ec2.connect_to_region(region_name)

    assert _is_iso_time(end)
    assert _is_iso_time(start)

    hist = conn.get_spot_price_history(start_time=start, end_time=end,
                                       availability_zone=zone,
                                       instance_type=instance_type,
                                       product_description=pdesc)

    if not hist:
        return False
    dates = []
    prices = []
    data = []
    for item in hist:
        timestamp = _iso_to_javascript_timestamp(item.timestamp)
        price = item.price
        dates.append(timestamp)
        prices.append(price)
        data.append([timestamp, price])
    maximum = max(prices)
    avg = sum(prices) / float(len(prices))

    print ("Current price: $%.4f" % prices[0])
    print ("Max price: $%.4f" % maximum)
    print ("Average price: $%.4f" % avg)
