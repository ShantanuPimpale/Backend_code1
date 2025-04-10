const amqp = require("amqplib");

let rabbitMQConnection;
let rabbitMQChannel;

async function getRabbitMQChannel() {
  if (rabbitMQChannel) {
    return rabbitMQChannel;
  }

  if (!rabbitMQConnection) {
    rabbitMQConnection = await amqp.connect(process.env.RABBITMQ_URL || "amqp://localhost");
  }

  rabbitMQChannel = await rabbitMQConnection.createChannel();
  await rabbitMQChannel.assertQueue("User", { durable: true });

  return rabbitMQChannel;
}

async function closeRabbitMQConnection() {
  if (rabbitMQChannel) {
    await rabbitMQChannel.close();
    rabbitMQChannel = null;
  }

  if (rabbitMQConnection) {
    await rabbitMQConnection.close();
    rabbitMQConnection = null;
  }
}

module.exports = {
  getRabbitMQChannel,
  closeRabbitMQConnection
};