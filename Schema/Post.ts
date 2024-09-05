import mongoose, { Document, Model, Schema, Types } from 'mongoose';

// Define an interface for the Message document
interface IMessage extends Document {
    id: string;
    u_id: string;
    from?: string;
    to: string;
    message: string;
    m_count: number;
    cam_id?: string;
    m_schedule?: string;
    status: string;
}

// Define the Message schema
const MessageSchema: Schema<IMessage> = new Schema({
    id: { type: String, required: true },
    u_id: { type: String, required: true }, // User ID to link messages to a user
    from: { type: String, required: false },
    to: { type: String, required: true },
    message: { type: String, required: true },
    m_count: { type: Number, required: true },
    cam_id: { type: String, required: false },
    m_schedule: { type: String, required: false },
    status: { type: String, required: true }
}, { timestamps: true });

// Define the Message model
const MessageModel: Model<IMessage> = mongoose.model<IMessage>('MessageHandler', MessageSchema);

// Define an interface for the Sign document

interface ISign extends Document {
  id?: string;
  Name?: string;
  Email: string;
  Password?: string;
  PhoneNumber?: string;
  Role?: string;
  Organization?: string;
  verificationToken?: string | null;
  verificationTokenExpiry?: Date | null;
  isVerified: boolean;
  Details: {
      PackageName?: string | null;
      PackageExpiry?: Date | null;
      Coins?: number | null;
      Status?: string | null;
  };
  messages: Types.ObjectId[]; // References to MessageModel
  package: Types.ObjectId[];  // References to PackageModel (use ObjectId[] for an array of ObjectIds)
}

const SignSchema: Schema<ISign> = new Schema({
  id: { type: String },
  Name: { type: String },
  Email: { type: String, required: true, unique: true },
  Password: { type: String },
  PhoneNumber: { type: String },
  Role: { type: String },
  Organization: { type: String },
  verificationToken: { type: String, default: null },
  verificationTokenExpiry: { type: Date, default: null },
  isVerified: { type: Boolean, default: false },
  Details: {
      PackageName: { type: String, default: null },
      PackageExpiry: { type: Date, default: null },
      Coins: { type: Number, default: null },
      Status: { type: String , default: null }
  },
  messages: [{ type: Schema.Types.ObjectId, ref: 'MessageModel' }],
  package: [{ type: Schema.Types.ObjectId, ref: 'PackageModel' }]
}, { timestamps: true });
// Define the Sign model
const SignModel: Model<ISign> = mongoose.model<ISign>('SignHandler', SignSchema);

// Define an interface for the Token document
interface IToken extends Document {
    Token: string;
}

// Define the Token schema
const TokenSchema: Schema<IToken> = new Schema({
    Token: { type: String, required: true, unique: true }
}, { timestamps: true });

// Define the Token model
const TokenModel: Model<IToken> = mongoose.model<IToken>('TokenHandler', TokenSchema);

export {
    IMessage,
    ISign,
    IToken,
    MessageModel,
    SignModel,
    TokenModel
};
