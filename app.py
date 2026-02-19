@app.route('/decrypt-and-return', methods=['POST'])
def decrypt_and_return():
    """Decripta e retorna o arquivo como bytes raw"""
    try:
        data = request.json
        file_url = data.get('url', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')
        mime_type = data.get('mimeType', 'video/mp4')

        print(f"=== DECRYPT-AND-RETURN v5.1 (binary) ===", file=sys.stderr)
        print(f"URL: {file_url[:80]}...", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)

        if not file_url:
            return jsonify({'error': 'url is required'}), 400
        if not media_key_b64:
            return jsonify({'error': 'mediaKey is required'}), 400

        # Decode mediaKey
        try:
            missing_padding = 4 - len(media_key_b64) % 4
            if missing_padding != 4:
                media_key_b64 = media_key_b64 + '=' * missing_padding
            media_key_bytes = base64.b64decode(media_key_b64)
        except Exception as e:
            return jsonify({'error': f'mediaKey decode failed: {str(e)}'}), 400

        if len(media_key_bytes) != 32:
            return jsonify({'error': f'Invalid media key: {len(media_key_bytes)} bytes'}), 400

        # Download
        print(f"Downloading...", file=sys.stderr)
        resp = requests.get(file_url, timeout=300)
        resp.raise_for_status()
        encrypted_data = resp.content
        print(f"Downloaded {len(encrypted_data)} bytes", file=sys.stderr)

        if len(encrypted_data) < 100:
            return jsonify({
                'error': f'File too small ({len(encrypted_data)} bytes) - URL may have expired'
            }), 400

        # Decrypt
        print(f"Decrypting...", file=sys.stderr)
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        del encrypted_data
        print(f"Decrypted {len(decrypted)} bytes, returning raw binary", file=sys.stderr)

        # Retorna bytes raw em vez de base64 JSON
        return Response(
            decrypted,
            mimetype=mime_type,
            headers={
                'Content-Disposition': 'attachment',
                'Content-Length': str(len(decrypted))
            }
        )

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500
