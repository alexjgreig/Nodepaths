use bindings::Windows::Networking::Sockets::StreamSocket;
use bindings::Windows::Storage::Streams::DataReader;
use bindings::Windows::Storage::Streams::DataWriter;

use windows::HSTRING;

pub struct SocketReaderWriter {
    pub data_reader: DataReader,
    pub data_writer: DataWriter,
    pub stream_socket: StreamSocket,
}

impl SocketReaderWriter {
    fn new(socket: StreamSocket) -> Self {
        let data_reader = DataReader::new();
        data_reader.UnicodeEncoding(UnicodeEncoding::Utf8);
        data_reader.ByteOrder(ByteOrder::LittleEdian);

        let data_writer = DataWriter::new();
        data_writer.UnicodeEncoding(UnicodeEncoding::Utf8);
        data_writer.ByteOrder(ByteOrder::LittleEdian);

        SocketReaderWriter {
            data_reader: data_reader,
            data_writer: data_writer,
            stream_socket: socket,
        }
    }
    fn close(&self) {
        &self.data_reader.Close();
        &self.data_writer.Close();
        &self.stream_socket.Close();
    }

    async fn write_message_async(&self, message: HSTRING) {
        &self
            .data_writer
            .WriteUInt32(data_writer.MeasureString(message));
        &self.data_writer.WriteString(message);
        &self.data_writer.StoreAsync().await;
        println!("Sent Message {:?}", message);
        //error handling
    }
    async fn read_message_async(&self) -> HSTRING {
        let bytes_read: u32 = &self.data_reader.LoadAsync(u32::Max);
        if bytes_read > 0 {
            let message_length: u32 = &self.data_reader.ReadUInt32();
            bytes_read = &self.data_reader.LoadAsync(message_length).await;
            if bytes_read > 0 {
                let message: HSTRING = &self.data_reader.ReadString(message_length);
                println!("Receieved Message: {:?}", message);
                return message;
            }
        }
        return ptr::null_mut();
    }
}
