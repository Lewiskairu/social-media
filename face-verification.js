const faceapi = require('face-api.js');
const { Canvas, Image, ImageData } = require('canvas');
const sharp = require('sharp');
const path = require('path');

// Configure face-api.js
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

async function loadModels() {
  const modelsPath = path.join(__dirname, 'models');
  await faceapi.nets.ssdMobilenetv1.loadFromDisk(modelsPath);
  await faceapi.nets.faceLandmark68Net.loadFromDisk(modelsPath);
  await faceapi.nets.faceRecognitionNet.loadFromDisk(modelsPath);
}

async function verifyFaces(idPhotoPath, selfiePath) {
  // Process images
  const [idBuffer, selfieBuffer] = await Promise.all([
    sharp(idPhotoPath).resize(800).jpeg().toBuffer(),
    sharp(selfiePath).resize(800).jpeg().toBuffer()
  ]);

  // Detect faces
  const [idDetection, selfieDetection] = await Promise.all([
    faceapi.detectSingleFace(new Image(idBuffer))
      .withFaceLandmarks()
      .withFaceDescriptor(),
    faceapi.detectSingleFace(new Image(selfieBuffer))
      .withFaceLandmarks()
      .withFaceDescriptor()
  ]);

  if (!idDetection || !selfieDetection) {
    throw new Error('Could not detect faces in both images');
  }

  // Calculate similarity
  const distance = faceapi.euclideanDistance(
    idDetection.descriptor,
    selfieDetection.descriptor
  );

  return {
    verified: distance < 0.6,
    similarity: Math.round((1 - distance) * 100),
    message: distance < 0.6 
      ? 'Identity verified successfully' 
      : 'Faces do not match'
  };
}

module.exports = { loadModels, verifyFaces };