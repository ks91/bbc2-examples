#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for backchain functionality
"""
import argparse
import os
import time
import requests
import json
import binascii
from datetime import datetime

def create_test_files(directory, a_value):
    """Create test files in the specified directory"""
    n = 200 + a_value
    print(f"Creating {n} test files in {directory}")
    
    # Record the start time
    start_time = int(time.time())
    print(f"File creation started at: {datetime.fromtimestamp(start_time)}")
    
    for i in range(1, n + 1):
        filename = f"{i}.txt"
        filepath = os.path.join(directory, filename)
        
        with open(filepath, 'w') as f:
            f.write(str(i))
        
        print(f"Created {filename}")
        time.sleep(1)  # 1 second interval
    
    print(f"Created all {n} files. Waiting 60 seconds for recording to complete...")
    time.sleep(60)
    
    return start_time

def get_records_from_api(rec_api_url, time_from, time_to):
    """Get records from the rec-api"""
    try:
        HEADERS = {'Content-Type': 'application/json'}
        dParam = {
            'timefrom': time_from,
            'timeto': time_to
        }
        response = requests.get(
            f"{rec_api_url}/records",
            headers=HEADERS,
            data=json.dumps(dParam, indent=2)
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting records: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"Exception getting records: {e}")
        return None

def verify_record(record, certify_api_url, evi_api_url, rec_api_url):
    """Verify a single record using the same logic as views.py"""
    try:
        filename = record.get('filename', 'unknown')
        
        # Create Record object from dict
        from recorder_tool import Record, get_record_dict, get_document, get_digest
        rec_obj = Record.from_dict(record)
        
        dVer = None
        lTimeSigned = None
        
        if rec_obj.sig:
            # Direct verification for checkpoint records
            dVer = get_record_dict(rec_obj)
            lTimeSigned = record.get('timestamp')
        else:
            # Forward traversal to checkpoint (BFS)
            from collections import deque
            visited_digests = set()
            start_digest = binascii.b2a_hex(rec_obj.get_signed_data()).decode()
            queue = deque([start_digest])
            found_checkpoint = False
            traversal_count = 0
            
            while queue and traversal_count < 100:  # Limit to prevent infinite loops
                current_digest = queue.popleft()
                if current_digest in visited_digests:
                    continue
                visited_digests.add(current_digest)
                traversal_count += 1
                
                # Show the current path being traversed
                # Remove traversal display for normal operation
                pass
                
                dParam = {'digest': current_digest}
                r = requests.post(f"{rec_api_url}/forward", headers={'Content-Type': 'application/json'}, 
                                data=json.dumps(dParam, indent=2))
                if r.status_code != 200:
                    print(f"Forward search failed for {filename}")
                    return False
                
                forward_records = r.json().get('records', [])
                if not forward_records:
                    continue
                
                # Check for anomalies
                # Remove debug output for normal operation
                pass
                
                # Check if any forward records are actually lost
                lost_in_path = []
                for fwd in forward_records:
                    fwd_filename = fwd.get('filename', 'unknown')
                    # Check if this record is actually lost by querying the database
                    lost_check_response = requests.get(
                        f"{rec_api_url}/records",
                        headers={'Content-Type': 'application/json'},
                        data=json.dumps({'timefrom': fwd.get('timestamp'), 'timeto': fwd.get('timestamp')}, indent=2)
                    )
                    if lost_check_response.status_code == 200:
                        records_data = lost_check_response.json()
                        for record in records_data.get('records', []):
                            if record.get('filename') == fwd_filename:
                                # This record exists in the database, so it's not lost
                                break
                        else:
                            # Record not found in database, so it's lost
                            lost_in_path.append(fwd_filename)
                
                if lost_in_path:
                    print(f"ERROR: {filename} - Found lost records in forward path: {lost_in_path}")
                
                for fwd in forward_records:
                    fwd_obj = Record.from_dict(fwd)
                    if fwd_obj.sig:
                        dVer = get_record_dict(fwd_obj)
                        lTimeSigned = fwd.get('timestamp')
                        found_checkpoint = True
                        # Remove checkpoint found messages for normal operation
                        pass
                        break
                    next_digest = binascii.b2a_hex(fwd_obj.get_signed_data()).decode()
                    if next_digest not in visited_digests:
                        queue.append(next_digest)
                
                if found_checkpoint:
                    break
            
            if traversal_count >= 1000:
                print(f"ERROR: {filename} - Traversal limit exceeded")
                return False
            
            if not found_checkpoint or dVer is None:
                print(f"ERROR: {filename} - No checkpoint found after {traversal_count} traversals")
                return False
        
        # Common verification logic
        document = get_document(dVer)
        digest = get_digest(document)
        dParam = {
            'digest': binascii.b2a_hex(digest).decode()
        }
        
        # Get proof from evidence service
        r = requests.get(f"{evi_api_url}/proof", headers={'Content-Type': 'application/json'}, 
                        data=json.dumps(dParam, indent=2))
        if r.status_code != 200:
            print(f"Failed to get proof for {filename}: {r.status_code}")
            return False
        
        res = r.json()
        dVer['proof'] = res['proof']
        
        # Verify using certify-api
        r = requests.get(f"{certify_api_url}/verify", headers={'Content-Type': 'application/json'}, 
                        data=json.dumps(dVer, indent=2))
        if r.status_code != 200:
            print(f"Verification request failed for {filename}: {r.status_code}")
            return False
        
        res = r.json()
        # Remove verification response display for normal operation
        pass
        if res.get('result') == 'valid' or res.get('time') is not None:
            return True
        else:
            print(f"Verification failed for {filename}: result={res.get('result')}, time={res.get('time')}")
            return False
            
    except Exception as e:
        print(f"Exception verifying record {record.get('filename')}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Test backchain functionality')
    parser.add_argument('directory', help='Directory to create test files in')
    parser.add_argument('a', type=int, help='Value for a parameter')
    parser.add_argument('--rec-api', default='http://localhost:5000/rec-api',
                       help='Recorder API URL')
    parser.add_argument('--certify-api', default='http://localhost:9000/certify-api',
                       help='Certify API URL')
    parser.add_argument('--evi-api', default='http://localhost:5000/evi-api',
                       help='Evidence API URL')
    parser.add_argument('--skip-file-creation', action='store_true',
                       help='Skip file creation and go directly to verification')
    
    args = parser.parse_args()
    
    if not args.skip_file_creation:
        # Create test files
        if not os.path.exists(args.directory):
            os.makedirs(args.directory)
        
        start_time = create_test_files(args.directory, args.a)
    else:
        # If skipping file creation, use current time as start time
        # (assuming files were created recently)
        start_time = int(time.time()) - 300  # 5 minutes ago
    
    # Get current time for record retrieval
    current_time = int(time.time())
    # Look for records from the start time onwards
    time_from = start_time
    time_to = current_time
    
    print(f"Retrieving records from {datetime.fromtimestamp(time_from)} to {datetime.fromtimestamp(time_to)}")
    
    # Get records
    records_data = get_records_from_api(args.rec_api, time_from, time_to)
    
    if not records_data or 'records' not in records_data:
        print("No records found or invalid response")
        return
    
    records = records_data['records']
    print(f"Found {len(records)} total records")
    
    # Filter records for files 1.txt to 200.txt
    target_records = []
    for record in records:
        filename = record.get('filename', '')
        if filename.endswith('.txt'):
            try:
                file_num = int(filename[:-4])  # Remove .txt and convert to int
                if 1 <= file_num <= 200:
                    target_records.append(record)
            except ValueError:
                continue
    
    print(f"Found {len(target_records)} records for files 1.txt to 200.txt")
    
    # Verify records
    successful_verifications = 0
    total_records = len(target_records)
    signed_records = 0
    
    for record in target_records:
        filename = record.get('filename', 'unknown')
        print(f"Verifying {filename}...")
        
        # Remove backchain info display for normal operation
        pass
        
        if record.get('sig'):
            signed_records += 1
        
        if verify_record(record, args.certify_api, args.evi_api, args.rec_api):
            successful_verifications += 1
            print(f"✓ {filename} verified successfully")
        else:
            print(f"✗ {filename} verification failed")
    
    # Calculate statistics
    lost_records = 200 - len(target_records)
    success_rate = (successful_verifications / total_records * 100) if total_records > 0 else 0
    
    print("\n" + "="*50)
    print("VERIFICATION RESULTS")
    print("="*50)
    print(f"Expected records (1.txt to 200.txt): 200")
    print(f"Retrieved records: {len(target_records)}")
    print(f"Lost records: {lost_records}")
    print(f"Signed records (checkpoints): {signed_records}")
    print(f"Successful verifications: {successful_verifications}")
    print(f"Success rate: {success_rate:.1f}%")
    print("="*50)

if __name__ == '__main__':
    main() 