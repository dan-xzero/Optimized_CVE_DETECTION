import os
import argparse
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

def upload_file_to_slack(token, file_path, channels, initial_comment=None, thread_ts=None):
    """
    Upload a file to Slack using the current Slack API.
    
    Args:
        token (str): Slack API token
        file_path (str): Path to the file to upload
        channels (str): Comma-separated list of channel IDs or names
        initial_comment (str, optional): Comment to add to the file
        thread_ts (str, optional): Thread timestamp to upload the file into
    
    Returns:
        dict: Response from the Slack API
    """
    # Initialize the Slack client
    client = WebClient(token=token)
    
    # Check if file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist")
    
    # Split the channels string into a list
    channel_list = channels.split(',')
    print(f"Attempting to upload to channels: {channel_list}")
    
    # Prepare the upload parameters for files_upload_v2
    # Important: Don't use channel_id parameter - use channels parameter
    upload_params = {
        'channels': channel_list,  # Pass the list directly
        'file': file_path
    }
    
    # Add optional parameters if provided
    if initial_comment:
        upload_params['initial_comment'] = initial_comment
    
    if thread_ts:
        upload_params['thread_ts'] = thread_ts
    
    try:
        # Try the upload with files_upload_v2
        print("Attempting upload with files_upload_v2...")
        response = client.files_upload_v2(**upload_params)
        print(f"File uploaded successfully: {response['file']['name']}")
        return response
    except SlackApiError as e:
        error_message = e.response["error"]
        print(f"Failed with files_upload_v2: {error_message}")
        
        # Try alternative approach
        try:
            print("Trying alternative approach with file chunk uploads...")
            # Read file as binary
            with open(file_path, 'rb') as file_content:
                # Use conversations_upload_file - new approach in Slack SDK that
                # handles large files better by using chunked uploads
                for channel in channel_list:
                    try:
                        response = client.files_upload_v2(
                            channel=channel,  # Use single channel
                            file=file_path,
                            initial_comment=initial_comment if initial_comment else None,
                            thread_ts=thread_ts if thread_ts else None
                        )
                        print(f"Successfully uploaded to channel {channel}")
                        return response
                    except SlackApiError as channel_error:
                        print(f"Failed to upload to channel {channel}: {channel_error.response['error']}")
            
            raise ValueError("Could not upload to any of the specified channels")
        except Exception as alt_error:
            print(f"All upload methods failed: {str(alt_error)}")
            
            # One final attempt: make a direct API call using requests
            try:
                print("Making final attempt with direct API call...")
                import requests
                
                with open(file_path, 'rb') as file_content:
                    files = {'file': file_content}
                    data = {
                        'channels': channels,
                        'token': token
                    }
                    
                    if initial_comment:
                        data['initial_comment'] = initial_comment
                    if thread_ts:
                        data['thread_ts'] = thread_ts
                        
                    response = requests.post(
                        'https://slack.com/api/files.upload', 
                        data=data,
                        files=files
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('ok', False):
                            print("Success with direct API call!")
                            return result
                        else:
                            print(f"Direct API call failed: {result.get('error', 'Unknown error')}")
                    else:
                        print(f"Direct API call failed with status code: {response.status_code}")
            except Exception as direct_error:
                print(f"Direct API call failed: {str(direct_error)}")
            
            raise

def main():
    parser = argparse.ArgumentParser(description='Upload a file to Slack')
    parser.add_argument('--token', required=True, help='Slack API token')
    parser.add_argument('--file', required=True, help='Path to file to upload')
    parser.add_argument('--channels', required=True, help='Comma-separated list of channel IDs')
    parser.add_argument('--comment', help='Initial comment for the file')
    parser.add_argument('--thread', help='Thread timestamp to upload the file into')
    
    args = parser.parse_args()
    
    try:
        # Verify token format
        if not args.token.startswith('xoxb-') and not args.token.startswith('xoxp-'):
            print("Warning: Token format doesn't look correct, should start with 'xoxb-' or 'xoxp-'")
        
        # Verify file exists
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            exit(1)
        
        # Print token info for debugging (safe version)
        token_prefix = args.token[:10] if len(args.token) > 10 else args.token
        print(f"Using token starting with: {token_prefix}...")
        
        # Check file size
        file_size = os.path.getsize(args.file)
        print(f"File size: {file_size} bytes")
        
        # Do upload
        upload_file_to_slack(
            token=args.token,
            file_path=args.file,
            channels=args.channels,
            initial_comment=args.comment,
            thread_ts=args.thread
        )
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()