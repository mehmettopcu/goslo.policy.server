#!/bin/bash

# Default values
DURATION=60  # Test duration in seconds
PARALLEL=10  # Number of parallel requests
HOST="http://localhost:8082"
INTERVAL=0.1 # Interval between requests in seconds

# Help function
show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -d, --duration   Test duration in seconds (default: 60)"
    echo "  -p, --parallel   Number of parallel requests (default: 10)"
    echo "  -h, --host      Host URL (default: http://localhost:8082)"
    echo "  -r, --rule      Rule to test (default: context_is_admin)"
    echo "  -i, --interval   Interval between requests in seconds (default: 0.1)"
    echo "  --help          Show this help message"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -r|--rule)
            RULE="$2"
            shift 2
            ;;
        -i|--interval)
            INTERVAL="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Create temporary files for storing results
RESULTS_FILE=$(mktemp)
STATS_FILE=$(mktemp)
SORTED_FILE=$(mktemp)

# Cleanup function to remove temporary files and kill background processes
cleanup() {
    rm -f "$RESULTS_FILE" "$STATS_FILE" "$SORTED_FILE"
    kill $(jobs -p) 2>/dev/null
}

# Register cleanup function to run on script exit
trap cleanup EXIT

# Function to make a single request and measure latency
make_request() {
    start_time=$(date +%s.%N)
    response=$(curl -s -w "\n%{time_total}\n" -X POST "$HOST/enforce" \
        -H "Content-Type: application/json" \
        -d '{
            "service": "nova",
            "rule": "$RULE",
            "credentials": {
                "user_id": "dc4c2b4671834f2490ff400e4813e4e1",
                "project_id": "b21d82371f224c6b2386ae2c5b0812b0",
                "roles": ["admin","member"]
            },
            "target": {
                "project_id": "b21d82371f224c6b2386ae2c5b0812b0"
            }
        }')
    echo "$response" | tail -n1 >> "$RESULTS_FILE"
}

# Function to run parallel requests for the specified duration
run_parallel_requests() {
    end_time=$((SECONDS + DURATION))
    
    while [ $SECONDS -lt $end_time ]; do
        for ((i=1; i<=PARALLEL; i++)); do
            make_request &
        done
        wait
        sleep "$INTERVAL"
    done
}

echo "Starting benchmark..."
echo "Duration: $DURATION seconds"
echo "Parallel requests: $PARALLEL"
echo "Host: $HOST"
echo "Interval: $INTERVAL seconds"
echo

# Run the benchmark
run_parallel_requests

# Sort the results for percentile calculations
sort -n "$RESULTS_FILE" > "$SORTED_FILE"

# Calculate and display statistics
echo "Calculating statistics..."
{
    echo "Statistics:"
    echo "==========="
    echo "Sample count: $(wc -l < "$SORTED_FILE")"
    echo "Average latency: $(awk '{ total += $1 } END { print total/NR " seconds" }' "$SORTED_FILE")"
    echo "Min latency: $(head -n1 "$SORTED_FILE") seconds"
    echo "Max latency: $(tail -n1 "$SORTED_FILE") seconds"
    
    # Calculate percentiles
    total_lines=$(wc -l < "$SORTED_FILE")
    p50_line=$((total_lines * 50 / 100))
    p90_line=$((total_lines * 90 / 100))
    p95_line=$((total_lines * 95 / 100))
    p99_line=$((total_lines * 99 / 100))
    
    echo "P50 latency: $(sed -n "${p50_line}p" "$SORTED_FILE") seconds"
    echo "P90 latency: $(sed -n "${p90_line}p" "$SORTED_FILE") seconds"
    echo "P95 latency: $(sed -n "${p95_line}p" "$SORTED_FILE") seconds"
    echo "P99 latency: $(sed -n "${p99_line}p" "$SORTED_FILE") seconds"
    echo
    echo "Requests per second: $(awk -v duration="$DURATION" 'END {print NR/duration}' "$SORTED_FILE")"
} | tee "$STATS_FILE" 