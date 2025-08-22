#!/usr/bin/env python3

import re
from collections import defaultdict, Counter
from datetime import datetime
import statistics

# extracting the year using the user id
def extract_year(user_id):
   
    if user_id and len(user_id) >= 4 and user_id[:4].isdigit():
        return int(user_id[:4])
    return None

#converting all units of osecond timings into float
def parse_microseconds(time_str):
    time_str = time_str.replace("Â", "")  # cleaning the data

   
    if 'n' in time_str and 'ns' not in time_str:  
        return float(time_str.replace('n', '')) / 1000

    elif 'ns' in time_str:  
        return float(time_str.replace('ns', '')) / 1000

    elif 'µs' in time_str:
        return float(time_str.replace('µs', ''))

    elif 'ms' in time_str:
        return float(time_str.replace('ms', '')) * 1000

    elif 's' in time_str and 'µs' not in time_str:
        return float(time_str.replace('s', '')) * 1_000_000

    return None


def parse_logfile(log_content):
 
    # Initializing the reqquired structures
    api_requests = []
    endpoint_requests = defaultdict(int)
    endpoint_response_times = defaultdict(list)
    unique_users = set()
    user_years = defaultdict(int)
    timetable_generations = []
    algorithm_usage = Counter()
    
    # Regular expressions for different log patterns
    api_request_pattern = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] (GET|POST) ([^\s]+) (\d{3}) (.+)'
    router_pattern = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] router: ([^\s\[]+)(?:\s+\[([^\]]+)\])?'
    timetable_pattern = r'timetable.*generated.*(?:backtracking|iterative|random)'
    algorithm_pattern = r'(?:backtracking|iterative.*random|random.*sampling)'
    
    lines = log_content.strip().split('\n')
    
    print(f"Processing {len(lines)} log lines...")
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
            
        try:
            # Match API request lines (with method, endpoint, status, and response time)
            api_match = re.match(api_request_pattern, line)
            if api_match:
                timestamp, ip, method, endpoint, status_code, response_time_str = api_match.groups()
                
                # Parse response time
                response_time = parse_microseconds(response_time_str)
                
                # Store API request data
                api_requests.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'method': method,
                    'endpoint': endpoint,
                    'status_code': int(status_code),
                    'response_time': response_time
                })
                
                # Count endpoint requests
                endpoint_requests[endpoint] += 1
                
                # Store response times for performance metrics
                endpoint_response_times[endpoint].append(response_time)
                
                continue
            
            # Match router lines (may contain user IDs)
            router_match = re.match(router_pattern, line)
            if router_match:
                timestamp, ip, endpoint, user_id = router_match.groups()
                
                if user_id:
                    # Add unique user
                    unique_users.add(user_id)
                    
                    # Extract and count user year
                    year = extract_year(user_id)
                    if year:
                        user_years[year] += 1
                
                continue
            
            # Check for timetable generation logs
            if re.search(timetable_pattern, line.lower()):
                timetable_generations.append(line)
                
                # Extract algorithm usage
                algorithm_match = re.search(algorithm_pattern, line.lower())
                if algorithm_match:
                    algorithm = algorithm_match.group()
                    if 'backtracking' in algorithm:
                        algorithm_usage['Backtracking'] += 1
                    elif 'iterative' in algorithm or 'random' in algorithm:
                        algorithm_usage['Iterative Random Sampling'] += 1
        
        except Exception as e:
            print(f"Warning: Error parsing line {line_num}: {e}")
            continue
    
    return {
        'api_requests': api_requests,
        'endpoint_requests': dict(endpoint_requests),
        'endpoint_response_times': dict(endpoint_response_times),
        'unique_users': unique_users,
        'user_years': dict(user_years),
        'timetable_generations': timetable_generations,
        'algorithm_usage': dict(algorithm_usage)
    }

def generate_report(parsed_data):
    """
    Generate comprehensive analytics report
    """
    api_requests = parsed_data['api_requests']
    endpoint_requests = parsed_data['endpoint_requests']
    endpoint_response_times = parsed_data['endpoint_response_times']
    unique_users = parsed_data['unique_users']
    user_years = parsed_data['user_years']
    timetable_generations = parsed_data['timetable_generations']
    algorithm_usage = parsed_data['algorithm_usage']
    
    report = []
    report.append("="*60)
    report.append("CC'S TIMETABLE GENERATOR - LOG ANALYSIS REPORT")
    report.append("="*60)
    report.append("")
    
    # Total API Requests
    total_requests = len(api_requests)
    successful_requests = len([r for r in api_requests if r['status_code'] == 200])
    failed_requests = total_requests - successful_requests
    
    report.append("TOTAL API REQUESTS SERVED")
    report.append("-" * 30)
    report.append(f"Total Requests: {total_requests:,}")
    report.append(f"Successful (200): {successful_requests:,}")
    report.append(f"Failed (4xx/5xx): {failed_requests:,}")
    report.append(f"Success Rate: {(successful_requests/total_requests*100):.1f}%" if total_requests > 0 else "Success Rate: N/A")
    report.append("")
    
    # Endpoint Popularity
    report.append("ENDPOINT POPULARITY")
    report.append("-" * 25)
    if endpoint_requests:
        sorted_endpoints = sorted(endpoint_requests.items(), key=lambda x: x[1], reverse=True)
        for endpoint, count in sorted_endpoints:
            percentage = (count / total_requests * 100) if total_requests > 0 else 0
            report.append(f"{endpoint:<30} {count:>8,} requests ({percentage:>5.1f}%)")
    else:
        report.append("No endpoint data found")
    report.append("")
    
    # Performance Metrics
    report.append("PERFORMANCE METRICS")
    report.append("-" * 25)
    if endpoint_response_times:
        report.append(f"{'Endpoint':<30} {'Avg Time':<12} {'Max Time':<12} {'Min Time':<12}")
        report.append("-" * 66)
        
        for endpoint in sorted(endpoint_response_times.keys()):
            times = endpoint_response_times[endpoint]
            if times:
                avg_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)
                
                # Format times appropriately
                def format_time(microseconds):
                    if microseconds >= 1000:
                        return f"{microseconds/1000:.2f}ms"
                    else:
                        return f"{microseconds:.2f}µs"
                
                report.append(f"{endpoint:<30} {format_time(avg_time):<12} {format_time(max_time):<12} {format_time(min_time):<12}")
    else:
        report.append("No performance data found")
    report.append("")
    
    # User Analytics
    report.append("USER ANALYTICS")
    report.append("-" * 20)
    total_unique_users = len(unique_users)
    report.append(f"Total Unique Users: {total_unique_users:,}")
    report.append("")
    
    if user_years:
        report.append("Users by Year:")
        sorted_years = sorted(user_years.items())
        for year, count in sorted_years:
            percentage = (count / total_unique_users * 100) if total_unique_users > 0 else 0
            report.append(f"  {year}: {count:,} users ({percentage:.1f}%)")
    else:
        report.append("No user year data found")
    report.append("")
    
    # Timetable Generation Insights
    report.append("TIMETABLE GENERATION INSIGHTS")
    report.append("-" * 35)
    
    total_timetables = len(timetable_generations)
    report.append(f"Total Timetables Generated: {total_timetables:,}")
    
    if total_unique_users > 0:
        avg_per_user = total_timetables / total_unique_users
        report.append(f"Average Timetables per User: {avg_per_user:.2f}")
    else:
        report.append("Average Timetables per User: N/A")
    
    report.append("")
    report.append("Algorithm Usage:")
    if algorithm_usage:
        total_algorithm_uses = sum(algorithm_usage.values())
        for algorithm, count in algorithm_usage.items():
            percentage = (count / total_algorithm_uses * 100) if total_algorithm_uses > 0 else 0
            report.append(f"  {algorithm}: {count:,} times ({percentage:.1f}%)")
    else:
        report.append("  No algorithm usage data found in logs")
    
    report.append("")
    report.append("="*60)
    report.append("End of Report")
    report.append("="*60)
    
    return "\n".join(report)

def main():
   
    try:
        # Read the log file content
        log_path = r"D:\BITS_Pilani\college\QUANT\Juniors_tasks\Question3\ProblemStatement3\ProblemStatement3\CC_task\timetable.log"
        
        with open(log_path, "r") as f:
            log_content = f.read()
        
        print("Starting log analysis...")
        
        # Parse the log content
        parsed_data = parse_logfile(log_content)
        
        # Generate and display the report
        report = generate_report(parsed_data)
        print(report)
        
        # Optionally save report to file
        # with open('log_analysis_report.txt', 'w') as f:
        #     f.write(report)
        # print("\nReport saved to 'log_analysis_report.txt'")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())